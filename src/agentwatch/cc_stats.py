"""Claude Code token usage statistics parser and analyzer.

Parses JSONL conversation logs from ~/.claude/projects/ to compute
token usage breakdowns by tool type and bash command category.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ToolCategory(Enum):
    """Categories for Claude Code tool usage."""

    Bash = "Bash"
    Read = "Read"
    Edit = "Edit"
    Write = "Write"
    Grep = "Grep"
    Glob = "Glob"
    Task = "Task"
    Web = "Web"
    MCP = "MCP"
    Planning = "Planning"
    Other = "Other"
    Thinking = "Thinking"


class BashCategory(Enum):
    """Sub-categories for bash/terminal commands."""

    Git = "Git"
    Testing = "Testing"
    PackageMgmt = "Package mgmt"
    ServerDev = "Server/dev"
    FileOps = "File ops"
    Process = "Process"
    Other = "Other"


# Pricing per million tokens: (input, output, cache_write, cache_read)
_PRICING = {
    "opus": (15.0, 75.0, 18.75, 1.50),
    "sonnet": (3.0, 15.0, 3.75, 0.30),
    "haiku": (1.0, 5.0, 1.25, 0.10),
}


def _get_pricing(model: str) -> tuple[float, float, float, float]:
    """Get per-million-token pricing for a model string."""
    model = model.lower()
    for key, rates in _PRICING.items():
        if key in model:
            return rates
    return _PRICING["sonnet"]  # default


@dataclass
class TrivialCall:
    """A single trivial tool call with context."""

    command: str
    total_tokens: int
    estimated_cost_usd: float
    session_id: str = ""
    user_prompt: str = ""


@dataclass
class TokenBucket:
    """Accumulated token counts for a category."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    call_count: int = 0

    @property
    def total_tokens(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_write_tokens
            + self.cache_read_tokens
        )

    def estimated_cost_usd(self, model: str = "sonnet") -> float:
        r = _get_pricing(model)
        return (
            self.input_tokens * r[0]
            + self.output_tokens * r[1]
            + self.cache_write_tokens * r[2]
            + self.cache_read_tokens * r[3]
        ) / 1_000_000

    def merge(self, other: TokenBucket) -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_write_tokens += other.cache_write_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.call_count += other.call_count


@dataclass
class StatsReport:
    """Aggregated token usage statistics."""

    by_tool: dict[ToolCategory, TokenBucket] = field(default_factory=dict)
    by_bash_category: dict[BashCategory, TokenBucket] = field(default_factory=dict)
    totals: TokenBucket = field(default_factory=TokenBucket)
    session_count: int = 0
    message_count: int = 0
    tool_call_count: int = 0
    project_name: str = ""
    model: str = "sonnet"
    trivial: TokenBucket = field(default_factory=TokenBucket)
    substantive: TokenBucket = field(default_factory=TokenBucket)
    top_trivial_commands: dict[str, int] = field(default_factory=dict)
    trivial_calls: list[TrivialCall] = field(default_factory=list)

    def merge(self, other: StatsReport) -> None:
        for cat, bucket in other.by_tool.items():
            if cat not in self.by_tool:
                self.by_tool[cat] = TokenBucket()
            self.by_tool[cat].merge(bucket)
        for cat, bucket in other.by_bash_category.items():
            if cat not in self.by_bash_category:
                self.by_bash_category[cat] = TokenBucket()
            self.by_bash_category[cat].merge(bucket)
        self.totals.merge(other.totals)
        self.session_count += other.session_count
        self.message_count += other.message_count
        self.tool_call_count += other.tool_call_count
        self.trivial.merge(other.trivial)
        self.substantive.merge(other.substantive)
        for cmd, count in other.top_trivial_commands.items():
            self.top_trivial_commands[cmd] = (
                self.top_trivial_commands.get(cmd, 0) + count
            )
        self.trivial_calls.extend(other.trivial_calls)
        # Prefer a concrete model name over the default
        if self.model == "sonnet" and other.model != "sonnet":
            self.model = other.model

    @property
    def cache_hit_ratio(self) -> float:
        total_cache = self.totals.cache_write_tokens + self.totals.cache_read_tokens
        if total_cache == 0:
            return 0.0
        return self.totals.cache_read_tokens / total_cache

    def to_dict(self) -> dict:
        return {
            "project": self.project_name,
            "model": self.model,
            "sessions": self.session_count,
            "messages": self.message_count,
            "tool_calls": self.tool_call_count,
            "totals": {
                "input_tokens": self.totals.input_tokens,
                "output_tokens": self.totals.output_tokens,
                "cache_write_tokens": self.totals.cache_write_tokens,
                "cache_read_tokens": self.totals.cache_read_tokens,
                "total_tokens": self.totals.total_tokens,
                "estimated_cost_usd": round(
                    self.totals.estimated_cost_usd(self.model), 2
                ),
                "cache_hit_ratio": round(self.cache_hit_ratio, 4),
            },
            "by_tool": {
                cat.value: {
                    "call_count": bucket.call_count,
                    "total_tokens": bucket.total_tokens,
                    "estimated_cost_usd": round(
                        bucket.estimated_cost_usd(self.model), 2
                    ),
                }
                for cat, bucket in sorted(
                    self.by_tool.items(),
                    key=lambda x: x[1].total_tokens,
                    reverse=True,
                )
            },
            "by_bash_category": {
                cat.value: {
                    "call_count": bucket.call_count,
                    "total_tokens": bucket.total_tokens,
                }
                for cat, bucket in sorted(
                    self.by_bash_category.items(),
                    key=lambda x: x[1].total_tokens,
                    reverse=True,
                )
            },
            "efficiency": {
                "trivial_calls": self.trivial.call_count,
                "trivial_tokens": self.trivial.total_tokens,
                "trivial_cost_usd": round(
                    self.trivial.estimated_cost_usd(self.model), 2
                ),
                "substantive_calls": self.substantive.call_count,
                "substantive_tokens": self.substantive.total_tokens,
                "substantive_cost_usd": round(
                    self.substantive.estimated_cost_usd(self.model), 2
                ),
                "trivial_pct": round(
                    self.trivial.total_tokens
                    / max(self.totals.total_tokens, 1)
                    * 100,
                    1,
                ),
                "top_trivial_commands": dict(
                    sorted(
                        self.top_trivial_commands.items(),
                        key=lambda x: x[1],
                        reverse=True,
                    )[:10]
                ),
            },
        }


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

_TOOL_MAP: dict[str, ToolCategory] = {
    "bash": ToolCategory.Bash,
    "read": ToolCategory.Read,
    "edit": ToolCategory.Edit,
    "write": ToolCategory.Write,
    "grep": ToolCategory.Grep,
    "glob": ToolCategory.Glob,
    "task": ToolCategory.Task,
    "webfetch": ToolCategory.Web,
    "websearch": ToolCategory.Web,
    "todoread": ToolCategory.Planning,
    "todowrite": ToolCategory.Planning,
    "enterplanmode": ToolCategory.Planning,
    "exitplanmode": ToolCategory.Planning,
    "notebookedit": ToolCategory.Edit,
}

# ---------------------------------------------------------------------------
# Trivial command detection
# ---------------------------------------------------------------------------

# Programs that any developer types regularly — no AI reasoning needed
_TRIVIAL_PROGRAMS = frozenset({
    # Git / GitHub
    "git", "gh",
    # Directory / file listing
    "ls", "pwd", "tree", "which", "type", "file",
    # File operations
    "mkdir", "cp", "mv", "rm", "touch", "chmod", "chown", "ln",
    "tar", "zip", "unzip", "rsync",
    # Viewing / output
    "echo", "printf", "cat", "head", "tail", "less", "more",
    "wc", "sort", "uniq", "tee", "diff",
    # Process management
    "ps", "kill", "pkill", "lsof", "top", "htop", "pgrep",
    "nohup", "screen", "tmux",
    # Package management
    "pip", "pip3", "npm", "yarn", "pnpm", "bun", "brew",
    "apt", "apt-get", "conda", "poetry", "pipx",
    # Server / dev
    "node", "uvicorn", "gunicorn", "flask", "next", "vite", "webpack",
    # Testing invocation
    "pytest", "jest", "vitest", "mocha", "phpunit",
    # Build
    "make", "cargo", "go", "tsc", "esbuild",
    # Misc
    "cd", "whoami", "date", "env", "export", "source", "open",
    "curl", "wget", "grep", "rg", "find", "xargs",
})


def _split_shell_commands(cmd: str) -> list[str]:
    """Split a shell command into individual sub-commands.

    Handles pipes (|), AND chains (&&), semicolons (;).
    Returns each sub-command as a separate string.
    """
    import re
    # Split on |, &&, ; while preserving quoted strings approximately
    parts = re.split(r'\s*(?:\|\||&&|[|;])\s*', cmd)
    return [p.strip() for p in parts if p.strip()]


# Programs that indicate AI-generated or complex invocations
_SUBSTANTIVE_PROGRAMS = frozenset({
    "awk", "sed",
    "claude",  # spawning AI agents
    "while", "for", "if", "do", "done", "then", "fi",  # shell constructs
})


def is_trivial_bash(cmd: str) -> bool:
    """Check if a bash command is trivial (user could type it themselves).

    Trivial = a well-known CLI command that doesn't require AI reasoning
    to formulate.  Non-trivial = inline code, complex text processing,
    shell constructs, AI agent spawning, or unknown programs.

    ALL sub-commands in a pipeline/chain must be trivial for the overall
    command to be trivial.
    """
    cmd = cmd.strip()
    if not cmd:
        return True

    # Check EVERY sub-command — ALL must be trivial
    for segment in _split_shell_commands(cmd):
        if not segment:
            continue

        parts = segment.split()
        idx = 0
        while idx < len(parts) and "=" in parts[idx] and not parts[idx].startswith("-"):
            idx += 1
        if idx >= len(parts):
            continue

        program = parts[idx].rsplit("/", 1)[-1].lower()
        rest_parts = parts[idx + 1:]

        # Explicitly substantive programs
        if program in _SUBSTANTIVE_PROGRAMS:
            return False

        # Inline code is substantive — the AI wrote the script
        if program in ("python", "python3", "node", "ruby", "perl"):
            if any(flag in rest_parts for flag in ("-c", "-e")):
                return False
            # Running a script file is trivial
            continue

        if program not in _TRIVIAL_PROGRAMS:
            return False

    return True


_GIT_PROGRAMS = frozenset({"git", "gh"})
_TEST_PROGRAMS = frozenset({"pytest", "jest", "vitest", "mocha", "phpunit"})
_PKG_PROGRAMS = frozenset({
    "pip", "pip3", "npm", "yarn", "pnpm", "bun", "brew",
    "apt", "apt-get", "conda", "poetry", "pipx",
})
_SERVER_PROGRAMS = frozenset({
    "node", "uvicorn", "gunicorn", "flask", "next", "vite", "webpack",
    "esbuild", "rollup", "parcel",
})
_FILE_PROGRAMS = frozenset({
    "mkdir", "cp", "mv", "rm", "chmod", "chown", "ln", "touch",
    "tar", "zip", "unzip", "rsync",
})
_PROCESS_PROGRAMS = frozenset({
    "ps", "kill", "pkill", "lsof", "top", "htop", "pgrep",
    "nohup", "screen", "tmux", "bg", "fg", "jobs",
})


def classify_tool_name(name: str) -> ToolCategory:
    """Map a tool name to its category."""
    cat = _TOOL_MAP.get(name.lower())
    if cat is not None:
        return cat
    # MCP tools often have a colon or prefix
    if ":" in name or name.startswith("mcp_"):
        return ToolCategory.MCP
    return ToolCategory.Other


def classify_bash_command(cmd: str) -> BashCategory:
    """Classify a bash command by its primary program."""
    cmd = cmd.strip()
    if not cmd:
        return BashCategory.Other

    # Take first command in pipeline/chain
    first_cmd = cmd.split("|")[0].strip()
    for sep in ("&&", ";"):
        first_cmd = first_cmd.split(sep)[0].strip()

    # Skip env var prefixes (KEY=VAL)
    parts = first_cmd.split()
    idx = 0
    while idx < len(parts) and "=" in parts[idx] and not parts[idx].startswith("-"):
        idx += 1
    if idx >= len(parts):
        return BashCategory.Other

    program = parts[idx].rsplit("/", 1)[-1].lower()
    rest = " ".join(parts[idx:]).lower()

    # Git
    if program in _GIT_PROGRAMS:
        return BashCategory.Git

    # Testing
    if program in _TEST_PROGRAMS:
        return BashCategory.Testing
    if program in ("python", "python3") and (
        "pytest" in rest or "unittest" in rest or "-m pytest" in rest
    ):
        return BashCategory.Testing
    if program == "npm" and "test" in rest:
        return BashCategory.Testing
    if program == "npx" and any(t in rest for t in ("jest", "vitest", "mocha")):
        return BashCategory.Testing
    if program in ("cargo", "go") and "test" in rest:
        return BashCategory.Testing
    if program == "make" and "test" in rest:
        return BashCategory.Testing

    # Package management
    if program in _PKG_PROGRAMS:
        if program in ("npm", "yarn", "pnpm", "bun"):
            if any(kw in rest for kw in ("install", "add", "remove", "uninstall", "ci")):
                return BashCategory.PackageMgmt
        elif program == "cargo" and any(kw in rest for kw in ("add", "install")):
            return BashCategory.PackageMgmt
        else:
            return BashCategory.PackageMgmt

    # Server / dev tooling
    if program in _SERVER_PROGRAMS:
        return BashCategory.ServerDev
    if program in ("npm", "npx", "yarn", "pnpm", "bun"):
        if any(kw in rest for kw in ("run", "start", "dev", "build", "serve")):
            return BashCategory.ServerDev
    if program in ("python", "python3") and any(
        kw in rest for kw in ("manage.py", "app.py", "server", "-m http", "runserver")
    ):
        return BashCategory.ServerDev

    # File operations
    if program in _FILE_PROGRAMS:
        return BashCategory.FileOps

    # Process management
    if program in _PROCESS_PROGRAMS:
        return BashCategory.Process

    return BashCategory.Other


# ---------------------------------------------------------------------------
# Project directory mapping
# ---------------------------------------------------------------------------

CLAUDE_PROJECTS_DIR = Path.home() / ".claude" / "projects"


def cwd_to_project_dir(cwd: Path | None = None) -> Path | None:
    """Map a working directory to its Claude Code project directory.

    Claude Code stores projects under ~/.claude/projects/ using the
    absolute path with '/' replaced by '-'.
    """
    if cwd is None:
        cwd = Path.cwd()
    cwd = cwd.resolve()
    # /Users/zaid/foo -> -Users-zaid-foo
    dir_name = str(cwd).replace("/", "-")
    project_dir = CLAUDE_PROJECTS_DIR / dir_name
    if project_dir.is_dir():
        return project_dir
    return None


def find_all_project_dirs() -> list[Path]:
    """Find all Claude Code project directories."""
    if not CLAUDE_PROJECTS_DIR.is_dir():
        return []
    return [p for p in CLAUDE_PROJECTS_DIR.iterdir() if p.is_dir()]


def project_dir_to_name(project_dir: Path) -> str:
    """Extract a readable project name from a project directory path."""
    name = project_dir.name  # e.g. -Users-zaid-Projects-agentwatch
    # Take the last component as the project name
    parts = name.strip("-").split("-")
    return parts[-1] if parts else name


# ---------------------------------------------------------------------------
# JSONL parsing
# ---------------------------------------------------------------------------


def _resolve_user_prompt(
    msg_id: str,
    parent_map: dict[str, str],
    user_messages: dict[str, str],
    max_depth: int = 10,
) -> str:
    """Walk the parentUuid chain to find the nearest user message."""
    current = parent_map.get(msg_id, "")
    for _ in range(max_depth):
        if not current:
            break
        if current in user_messages:
            return user_messages[current]
        # The parent might be another assistant chunk — walk further
        current = parent_map.get(current, "")
    return ""


def parse_session_stats(jsonl_path: Path) -> StatsReport:
    """Parse a single JSONL session file and compute token stats.

    Handles streaming deduplication: multiple JSONL lines with the same
    message.id are treated as a single API response. Token counts are
    taken as the maximum across all chunks (output_tokens grows as
    streaming progresses).
    """
    report = StatsReport(session_count=1)
    session_id = jsonl_path.stem

    # Pass 1: Group lines by message.id, index user messages
    messages: dict[str, dict] = {}
    user_messages: dict[str, str] = {}  # uuid -> content snippet
    parent_map: dict[str, str] = {}  # assistant first_uuid -> parentUuid

    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            line_type = obj.get("type")

            # Index user messages for prompt lookups
            if line_type == "user":
                uuid = obj.get("uuid", "")
                msg = obj.get("message", {})
                content = msg.get("content", "") if isinstance(msg, dict) else ""
                if isinstance(content, str) and uuid:
                    user_messages[uuid] = content[:200]
                elif isinstance(content, list) and uuid:
                    # Content can be a list of blocks
                    texts = [
                        b.get("text", "")
                        for b in content
                        if isinstance(b, dict) and b.get("type") == "text"
                    ]
                    user_messages[uuid] = " ".join(texts)[:200]
                continue

            if line_type != "assistant":
                continue

            msg = obj.get("message")
            if not isinstance(msg, dict):
                continue
            msg_id = msg.get("id")
            if not msg_id:
                continue

            usage = msg.get("usage")
            if not isinstance(usage, dict):
                continue

            if msg_id not in messages:
                messages[msg_id] = {
                    "model": msg.get("model", ""),
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cache_write": 0,
                    "cache_read": 0,
                    "tool_blocks": {},  # block_id -> (tool_name, tool_input)
                    "has_thinking": False,
                }
                # Track parentUuid from the first chunk of this message
                p_uuid = obj.get("parentUuid", "")
                if p_uuid:
                    parent_map[msg_id] = p_uuid

            md = messages[msg_id]

            # Take max across streaming chunks
            md["input_tokens"] = max(
                md["input_tokens"], usage.get("input_tokens", 0)
            )
            md["output_tokens"] = max(
                md["output_tokens"], usage.get("output_tokens", 0)
            )
            md["cache_write"] = max(
                md["cache_write"], usage.get("cache_creation_input_tokens", 0)
            )
            md["cache_read"] = max(
                md["cache_read"], usage.get("cache_read_input_tokens", 0)
            )
            if msg.get("model"):
                md["model"] = msg["model"]

            # Collect content blocks
            for block in msg.get("content", []):
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "tool_use":
                    bid = block.get("id", "")
                    if bid and bid not in md["tool_blocks"]:
                        md["tool_blocks"][bid] = (
                            block.get("name", ""),
                            block.get("input", {}),
                        )
                elif btype == "thinking":
                    md["has_thinking"] = True

    # Pass 2: Attribute tokens
    from collections import Counter

    model_counts: Counter[str] = Counter()

    for msg_id, md in messages.items():
        report.message_count += 1

        if md["model"]:
            model_counts[md["model"]] += 1

        tool_calls = list(md["tool_blocks"].values())

        # Build per-tool categories and track bash commands
        categories: list[ToolCategory] = []
        bash_commands: list[tuple[int, str]] = []  # (index_in_categories, cmd)

        for tool_name, tool_input in tool_calls:
            cat = classify_tool_name(tool_name)
            idx = len(categories)
            categories.append(cat)
            if cat == ToolCategory.Bash:
                cmd = (
                    tool_input.get("command", "")
                    if isinstance(tool_input, dict)
                    else ""
                )
                bash_commands.append((idx, cmd))

        report.tool_call_count += len(tool_calls)

        # If no tool calls, attribute to Thinking or Other
        if not categories:
            categories = [
                ToolCategory.Thinking if md["has_thinking"] else ToolCategory.Other
            ]

        n = len(categories)
        per_input = md["input_tokens"] // n
        per_output = md["output_tokens"] // n
        per_cw = md["cache_write"] // n
        per_cr = md["cache_read"] // n

        for i, cat in enumerate(categories):
            bucket = report.by_tool.setdefault(cat, TokenBucket())
            # Give remainder to last bucket
            extra = 1 if i == n - 1 else 0
            bucket.input_tokens += per_input + (
                md["input_tokens"] - per_input * n if extra else 0
            )
            bucket.output_tokens += per_output + (
                md["output_tokens"] - per_output * n if extra else 0
            )
            bucket.cache_write_tokens += per_cw + (
                md["cache_write"] - per_cw * n if extra else 0
            )
            bucket.cache_read_tokens += per_cr + (
                md["cache_read"] - per_cr * n if extra else 0
            )
            bucket.call_count += 1

        # Bash sub-categories
        bash_cmds_by_idx = dict(bash_commands)
        for cat_idx, cmd in bash_commands:
            bash_cat = classify_bash_command(cmd)
            sub = report.by_bash_category.setdefault(bash_cat, TokenBucket())
            sub.input_tokens += per_input
            sub.output_tokens += per_output
            sub.cache_write_tokens += per_cw
            sub.cache_read_tokens += per_cr
            sub.call_count += 1

        # Trivial vs substantive classification
        # Resolve user prompt for this message (walk parentUuid)
        _user_prompt: str | None = None

        for i, cat in enumerate(categories):
            trivial = False
            if cat == ToolCategory.Bash and i in bash_cmds_by_idx:
                cmd = bash_cmds_by_idx[i]
                if is_trivial_bash(cmd):
                    trivial = True
                    # Track command label for top-N display
                    label = cmd.split()[0].rsplit("/", 1)[-1] if cmd.strip() else "empty"
                    report.top_trivial_commands[label] = (
                        report.top_trivial_commands.get(label, 0) + 1
                    )

                    # Build detailed TrivialCall
                    call_tokens = per_input + per_output + per_cw + per_cr
                    tc = TrivialCall(
                        command=cmd,
                        total_tokens=call_tokens,
                        estimated_cost_usd=TokenBucket(
                            input_tokens=per_input,
                            output_tokens=per_output,
                            cache_write_tokens=per_cw,
                            cache_read_tokens=per_cr,
                        ).estimated_cost_usd(md.get("model", "sonnet")),
                        session_id=session_id,
                    )
                    # Lazily resolve user prompt once per message
                    if _user_prompt is None:
                        _user_prompt = _resolve_user_prompt(
                            msg_id, parent_map, user_messages
                        )
                    tc.user_prompt = _user_prompt
                    report.trivial_calls.append(tc)

            target = report.trivial if trivial else report.substantive
            target.input_tokens += per_input
            target.output_tokens += per_output
            target.cache_write_tokens += per_cw
            target.cache_read_tokens += per_cr
            target.call_count += 1

        # Totals (full amount, not split)
        report.totals.input_tokens += md["input_tokens"]
        report.totals.output_tokens += md["output_tokens"]
        report.totals.cache_write_tokens += md["cache_write"]
        report.totals.cache_read_tokens += md["cache_read"]
        report.totals.call_count += 1

    # Dominant model
    if model_counts:
        report.model = model_counts.most_common(1)[0][0]

    return report


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def compute_stats(
    *,
    project_dir: Path | None = None,
    all_projects: bool = False,
    session_id: str | None = None,
) -> StatsReport:
    """Compute token usage stats.

    Args:
        project_dir: Specific project directory. If None, uses CWD mapping.
        all_projects: If True, scan all projects under ~/.claude/projects/.
        session_id: If set, parse only this specific session.

    Returns:
        Merged StatsReport across all matching sessions.
    """
    merged = StatsReport()

    if all_projects:
        dirs = find_all_project_dirs()
    else:
        if project_dir is None:
            project_dir = cwd_to_project_dir()
        if project_dir is None:
            return merged
        dirs = [project_dir]

    for pdir in dirs:
        proj_name = project_dir_to_name(pdir)

        if session_id:
            jsonl = pdir / f"{session_id}.jsonl"
            files = [jsonl] if jsonl.is_file() else []
        else:
            files = sorted(pdir.glob("*.jsonl"))

        for jsonl_path in files:
            try:
                session_report = parse_session_stats(jsonl_path)
                merged.merge(session_report)
            except (OSError, json.JSONDecodeError):
                continue

        if not merged.project_name:
            merged.project_name = proj_name

    if all_projects:
        merged.project_name = f"all ({len(dirs)} projects)"

    return merged
