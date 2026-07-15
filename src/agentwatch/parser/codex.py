"""OpenAI Codex CLI rollout (JSONL) log parsing.

Codex CLI writes one JSONL "rollout" file per session under
``~/.codex/sessions/YYYY/MM/DD/rollout-<TIMESTAMP>-<UUID>.jsonl``. Each line
is a ``RolloutLine``-shaped envelope: a ``timestamp``/``type``/``payload``
wrapper around one of a handful of event kinds (``session_meta``,
``response_item``, ``event_msg``, ``turn_context``).

This module is a genuine departure from ``logs.py``'s per-format
``parse_*_entry(entry) -> Action | list[Action] | None`` stateless-function
shape, for two reasons:

1. Codex correlates a tool call to its result via a shared ``call_id``
   field present on both the ``function_call`` and ``function_call_output``
   lines, not via adjacency or a parent/child link the way Claude Code's
   assistant/user message pairing works — the two lines are not guaranteed
   to be adjacent (the model can emit narration in between), so calls must
   be buffered by ``call_id`` until their matching output arrives.
2. Codex's rollout schema has gone through multiple confirmed eras (see
   ``_detect_codex_era`` below), which needs some internal version-dispatch
   structure with no equivalent in any existing parser here.

**Fixture-based implementation, still not verified against a live Codex CLI
install** (see `PLAYBOOK.md` Sprint 4 and
``codex-cli-support-prd.md``'s "Open Questions / Requires Live Install to
Confirm" section) — but PLAYBOOK Sprint 8 (2026-07-14) closed the gap
between "guessed from research/issue trackers" and "read from the real
source" for several of the original Open Questions, by fetching
``codex-rs/protocol/src/protocol.rs`` and ``models.rs`` directly from
github.com/openai/codex @ main (public repo, no live install needed to read
its own current source).

**Open Question #1 — RESOLVED with direct primary-source evidence.**
``RolloutLine { timestamp, ordinal, #[serde(flatten)] item: RolloutItem }``
where ``RolloutItem`` is ``#[serde(tag = "type", content = "payload")]`` —
i.e. the two-level nesting this module always assumed
(``{"type": "response_item", "payload": {"type": "function_call", ...}}``)
is exactly right, confirmed from the struct definitions themselves, not
inferred. A previously-undocumented ``ordinal: Option<u64>`` field also
exists on every line (not currently extracted — low priority, timestamps
already provide ordering). ``ResponseItem`` (the ``response_item`` payload)
is itself internally tagged (``#[serde(tag = "type")]``, no further
nesting) with real ``FunctionCall`` fields matching this module's
extraction exactly: ``id: Option``, ``name: String``,
``arguments: String`` (JSON-encoded — confirms ``_coerce_json``'s
string-or-already-parsed handling), ``call_id: String``.

**Sprint 9 (2026-07-14) implemented the ExecCommandEnd/PatchApplyEnd
correlation Sprint 8 scoped out.** ``FunctionCallOutputPayload``'s real
``Deserialize`` impl hardcodes ``success: None`` and its wire shape is only
ever a plain string or a content-item array — never an object with
``success``/``error`` keys, so ``function_call_output`` carries no error
signal at all (see ``_extract_function_call_output``'s docstring). The REAL
success/failure signal for exec-type calls is a separate ``event_msg``
event, ``ExecCommandEnd`` (``codex-rs/protocol/src/protocol.rs``,
re-fetched and re-confirmed for this sprint: ``EventMsg`` is
``#[serde(tag = "type", rename_all = "snake_case")]``, so a rollout line
carrying it looks like ``{"type": "event_msg", "payload": {"type":
"exec_command_end", "call_id": ..., "exit_code": ..., "status": ...}}``) —
real fields ``call_id: String`` (same correlation id as the
``FunctionCall``), ``exit_code: i32``, ``status: ExecCommandStatus``
(``Completed | Failed | Declined``, ``rename_all = "snake_case"`` so wire
values are ``"completed"``/``"failed"``/``"declined"``), plus real
``stdout``/``stderr``/``formatted_output``. The parallel signal for
``apply_patch``-type calls, also newly confirmed this sprint, is
``PatchApplyEnd``: ``PatchApplyEndEvent { call_id: String, success: bool,
stdout: String, stderr: String, ... }`` — directly answers Sprint 8's open
question of "what carries success for apply_patch" (a plain, non-optional
``success: bool``, not a status enum).

``CodexParser`` now correlates this second event family by ``call_id``
into the same ``_pending`` dict ``function_call``/``function_call_output``
already use (see ``_extract_exec_command_end``/``_extract_patch_apply_end``
and ``_PendingCall.resolved_by_event_msg`` below for how the two signals
are reconciled without either duplicating or clobbering each other).

**Still genuinely open, even with this source access**: whether
``exec_command_end``/``patch_apply_end`` always co-occurs with a
``function_call_output`` for the same call, or can arrive alone with no
``function_call_output`` ever following, is not confirmed without a live
capture. The implementation handles both cases without guessing which is
real (see docstrings below), but that's a defensive design choice, not a
confirmed fact about the wire protocol. MCP tool call success/failure
(``McpToolCallEnd``, seen in the ``EventMsg`` enum but not extracted here)
remains unaddressed — out of scope for this sprint, flagged for a future
one alongside Open Questions #2/#5.

**Open Question #3 — PARTIALLY RESOLVED (2026-07-15)**, after Sprints 4, 8,
and 10 each attempted and found nothing: a real tool/function registry
exists in ``codex-rs`` (``codex-rs/core/src/tools/handlers/*_spec.rs``,
each building a ``ToolSpec`` with a literal ``name: "..."`` field — the
exact wire value the model calls). ``classify_codex_tool`` now hardcodes
the general-purpose subset confirmed there (``exec_command``,
``write_stdin``, ``shell_command``, ``view_image``, ``list_mcp_resources``,
``list_mcp_resource_templates``, ``read_mcp_resource``, ``tool_search``,
plus the pre-existing ``apply_patch``) — see
``_CONFIRMED_CODEX_TOOL_TYPES``'s docstring for exact file/line citations.
A much larger multi-agent-orchestration/plugin-management tool surface was
also found in the same registry (``spawn_agent``, ``send_input``,
``update_plan``, ``request_permissions``, etc.) but deliberately left
unmapped — a different feature (Codex coordinating its own sub-agents),
not this classifier's single-session file/exec/read vocabulary. Still
open: whether any of these real names actually appear in the specific
Codex CLI version an end user has installed (this registry is read from
``codex-rs`` @ ``main``, not a version-pinned release, and still no live
install exists to cross-check against — see module-level "not verified
against a live Codex CLI install" note above).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .logs import classify_tool
from .models import Action, ToolType

# Boundary between the "mid" and "new" (>=0.44) Codex rollout schema eras,
# per codex-trace's README (three confirmed eras: new >=0.44, mid, oldest
# 2025/08). The *field name* that carries this version in real Codex output
# (assumed here to be `cli_version`) is NOT confirmed — see Open Question #1.
_NEW_ERA_VERSION_BOUNDARY = (0, 44)


@dataclass
class _FunctionCall:
    """Extracted fields from a ``function_call`` response_item payload."""

    call_id: str | None
    name: str
    file_path: str | None
    command: str | None


@dataclass
class _FunctionCallOutput:
    """Extracted fields from a ``function_call_output`` response_item payload."""

    call_id: str | None
    is_error: bool
    error_text: str | None


@dataclass
class _ExecResult:
    """Extracted fields from an ExecCommandEnd or PatchApplyEnd event_msg
    payload -- the real success/failure signal for exec-type and
    apply_patch-type calls (see module docstring)."""

    call_id: str | None
    is_error: bool
    error_text: str | None


@dataclass
class _PendingCall:
    """A function_call seen but not yet matched to its output."""

    action: Action
    call_id: str
    # Set once an ExecCommandEnd/PatchApplyEnd event_msg has supplied a real
    # success/failure signal for this call, so the later (and strictly
    # weaker -- see _extract_function_call_output) function_call_output
    # signal doesn't clobber it back to a guessed success=True.
    resolved_by_event_msg: bool = False


#: Real Codex tool names confirmed directly against ``codex-rs``'s tool
#: registry (github.com/openai/codex @ main, fetched 2026-07-15 -- PRD Open
#: Question #3, partially resolved after Sprints 4/8/10 all attempted and
#: found nothing). Each ``ToolSpec`` literal ``name: "..."`` field below is
#: the exact wire value the model calls and that shows up in a real
#: ``function_call.name`` -- not inferred, read straight off the struct
#: construction:
#:   - ``codex-rs/core/src/tools/handlers/shell_spec.rs``: line 92
#:     (``exec_command``), line 142 (``write_stdin``), line 214
#:     (``shell_command``)
#:   - ``codex-rs/core/src/tools/handlers/apply_patch_spec.rs``: line 19
#:     (``apply_patch`` -- re-confirmed via the registry, already handled
#:     as a special case below since it predates this table)
#:   - ``codex-rs/protocol/src/models.rs``: line 1350,
#:     ``pub const VIEW_IMAGE_TOOL_NAME: &str = "view_image"`` -- the same
#:     file Sprint 8 already fetched and confirmed ``FunctionCall``'s wire
#:     shape from
#:   - ``codex-rs/core/src/tools/handlers/mcp_resource_spec.rs``: line 24
#:     (``list_mcp_resources``), line 52 (``list_mcp_resource_templates``),
#:     line 80 (``read_mcp_resource``)
#:   - ``codex-rs/tools/src/tool_discovery.rs``: line 6,
#:     ``pub const TOOL_SEARCH_TOOL_NAME: &str = "tool_search"``
#:
#: ``write_stdin`` is deliberately listed under BASH rather than left to
#: ``classify_tool``'s generic substring rules: it feeds input to an
#: already-running shell command (``unified_exec``), not a file write, so
#: the substring-based "write" -> WRITE guess it would otherwise hit is
#: wrong now that the real semantics are known.
#:
#: The registry also confirmed a large surface of real tool names this
#: table deliberately does NOT map: meta/control-flow tools with no
#: fitting ``ToolType`` (``request_permissions``, ``update_plan``,
#: ``new_context`` [``NEW_CONTEXT_WINDOW_TOOL_NAME``, ``new_context_window_
#: spec.rs`` line 6], ``request_user_input``, ``get_context_remaining``,
#: ``list_available_plugins_to_install``, ``request_plugin_install``), and
#: an entire separate multi-agent-orchestration tool family
#: (``spawn_agent``/``send_input``/``send_message``/``followup_task``/
#: ``resume_agent``/``wait_agent``/``list_agents``/``close_agent``/
#: ``interrupt_agent``, per ``multi_agents_spec.rs``, plus ``agent_jobs_
#: spec.rs``'s ``spawn_agents_on_csv``/``report_agent_job_result``) that
#: belongs to a genuinely different feature (Codex spawning/coordinating
#: its own sub-agents) outside this classifier's single-session file/exec/
#: read vocabulary. Forcing any of these into an existing ``ToolType``
#: would be a guess, not a confirmed mapping -- they fall through to
#: ``classify_tool``'s substring rules (mostly UNKNOWN) unchanged, same as
#: any other not-yet-confirmed name.
_CONFIRMED_CODEX_TOOL_TYPES: dict[str, ToolType] = {
    "exec_command": ToolType.BASH,
    "write_stdin": ToolType.BASH,
    "shell_command": ToolType.BASH,
    "view_image": ToolType.READ,
    "list_mcp_resources": ToolType.MCP,
    "list_mcp_resource_templates": ToolType.MCP,
    "read_mcp_resource": ToolType.MCP,
    "tool_search": ToolType.SEARCH,
}


def classify_codex_tool(name: str) -> ToolType:
    """Classify a Codex function-call name into a ToolType.

    Checks ``_CONFIRMED_CODEX_TOOL_TYPES`` (real names read directly off
    ``codex-rs``'s tool registry, see that table's docstring for citations)
    first, then ``apply_patch``/``apply-patch`` (Codex's documented
    file-edit mechanism) -> EDIT, then falls back to ``logs.classify_tool``
    's generic substring rules for anything not yet confirmed.

    Real tool names beyond what ``_CONFIRMED_CODEX_TOOL_TYPES`` covers do
    exist (a large multi-agent-orchestration/plugin-management surface --
    see that table's docstring) but are deliberately left unmapped rather
    than guessed into a ``ToolType`` that doesn't fit. Expect Codex actions
    using those still-unmapped names to classify as ``ToolType.UNKNOWN`` --
    documented, expected behavior, not a bug.
    """
    name_lower = name.lower()
    if name_lower in _CONFIRMED_CODEX_TOOL_TYPES:
        return _CONFIRMED_CODEX_TOOL_TYPES[name_lower]
    if "apply_patch" in name_lower or "apply-patch" in name_lower:
        return ToolType.EDIT
    return classify_tool(name)


def _era_for_version(version: str) -> str:
    """Map a Codex CLI version string to a schema era.

    Does a simple ``(major, minor)`` tuple comparison rather than pulling
    in the ``packaging`` package (not otherwise a project dependency) —
    sufficient for a single >=/< boundary check.
    """
    try:
        parts = version.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return "mid"
    return "new" if (major, minor) >= _NEW_ERA_VERSION_BOUNDARY else "mid"


def _detect_codex_era(entry: dict) -> str:
    """Sniff which Codex rollout schema era *entry* belongs to.

    Strategy: prefer an explicit version field if present
    (``payload.cli_version``/``entry.cli_version``, per the "new" era —
    exact key name unconfirmed, see Open Question #1), falling back to
    shape-sniffing (presence/absence of a ``payload`` wrapper) when no
    version field exists, which is the only option for the "oldest"
    (2025/08) era. Unrecognized shapes fall through to "oldest" (the most
    defensive, least-assuming extraction path).
    """
    payload = entry.get("payload", entry)
    version = None
    if isinstance(payload, dict):
        version = payload.get("cli_version")
    if not version:
        version = entry.get("cli_version")
    if version:
        return _era_for_version(str(version))
    if "payload" in entry and isinstance(entry.get("type"), str):
        return "mid"
    return "oldest"


def _coerce_json(value: Any) -> Any:
    """Best-effort JSON-decode a value that may already be a dict/list, a
    JSON-encoded string (Codex's ``arguments``/``output`` fields are
    plausibly serialized JSON strings, matching OpenAI function-calling
    conventions elsewhere), or something else entirely."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    return value


def _extract_function_call(payload: dict, era: str) -> _FunctionCall | None:
    """Extract a ``function_call`` response_item's fields from *payload*.

    ``era`` is accepted for future per-era field-name divergence (PRD
    section 3) but not yet branched on internally: the confirmed research
    found no evidence of *which* fields differ per era (only that the
    wrapper/version-field shape differs), so this stays a single
    extraction path until a real captured file proves otherwise —
    over-branching ahead of confirmed need would just be guessing twice.
    """
    del era  # reserved for future per-era divergence, see docstring
    if not isinstance(payload, dict) or payload.get("type") != "function_call":
        return None

    call_id = payload.get("call_id") or payload.get("id")
    name = payload.get("name") or "unknown"

    args = _coerce_json(payload.get("arguments"))
    file_path = None
    command = None
    if isinstance(args, dict):
        file_path = args.get("path") or args.get("file") or args.get("file_path")
        cmd = args.get("command")
        if isinstance(cmd, list):
            command = " ".join(str(c) for c in cmd)
        elif isinstance(cmd, str):
            command = cmd

    return _FunctionCall(call_id=call_id, name=name, file_path=file_path, command=command)


def _extract_function_call_output(payload: dict, era: str) -> _FunctionCallOutput | None:
    """Extract a ``function_call_output`` response_item's fields from
    *payload*. See ``_extract_function_call`` for the ``era`` rationale.

    **PLAYBOOK Sprint 8 correction (2026-07-14), direct primary-source
    evidence**: fetched the real, current ``codex-rs/protocol/src/models.rs``
    from github.com/openai/codex @ main. ``FunctionCallOutputPayload``'s
    ``Deserialize`` impl unconditionally sets ``success: None`` (never reads
    a ``success`` key off the wire), and its ``Serialize`` impl emits
    *only* the body — either a plain string or a JSON array of content
    items, never an object with ``success``/``error`` keys. The previous
    ``isinstance(output, dict)`` check this function used to run was
    checking for a shape that cannot occur on the wire (confirmed dead
    code, not just unconfirmed) — silently classifying every real
    ``function_call_output`` as success, including actual failures.
    ``is_error`` is honestly left ``False`` here (there is no error signal
    to read from *this* event) rather than a guessed heuristic on a string/
    list body. The REAL success/failure signal for exec-type calls is a
    separate, correlatable-by-``call_id`` ``event_msg`` (``ExecCommandEnd``,
    carrying ``exit_code``/``status: Completed|Failed|Declined``) — wired in
    as of Sprint 9 via ``_extract_exec_command_end``/``CodexParser``'s
    ``resolved_by_event_msg`` tracking, which is why this function's
    always-``False`` guess is safe: it only wins when nothing better showed
    up first.
    """
    del era  # reserved for future per-era divergence
    if not isinstance(payload, dict) or payload.get("type") != "function_call_output":
        return None

    call_id = payload.get("call_id") or payload.get("id")
    return _FunctionCallOutput(call_id=call_id, is_error=False, error_text=None)


def _extract_exec_command_end(payload: dict) -> _ExecResult | None:
    """Extract an ``ExecCommandEnd`` ``event_msg`` payload's real
    success/failure signal for exec-type (``shell``) calls.

    **Sprint 9 (2026-07-14), direct primary-source evidence**: fetched the
    real, current ``codex-rs/protocol/src/protocol.rs`` from
    github.com/openai/codex @ main. ``ExecCommandEndEvent`` has non-optional
    ``call_id: String``, ``exit_code: i32``, ``status: ExecCommandStatus``
    (``Completed | Failed | Declined``, wire values ``"completed"``/
    ``"failed"``/``"declined"`` per its ``rename_all = "snake_case"``), plus
    ``stdout``/``stderr``/``formatted_output``. ``status`` is the primary
    signal; a numeric ``exit_code`` fallback covers a malformed/missing
    ``status`` defensively without guessing when both are absent (real wire
    data always has both, per the non-optional Rust fields).
    """
    if not isinstance(payload, dict) or payload.get("type") != "exec_command_end":
        return None

    call_id = payload.get("call_id")
    status = payload.get("status")
    exit_code = payload.get("exit_code")
    if status in ("failed", "declined"):
        is_error = True
    elif status == "completed":
        is_error = False
    elif isinstance(exit_code, int):
        is_error = exit_code != 0
    else:
        # No real signal at all (malformed/test data) -- don't guess failure.
        is_error = False

    error_text = None
    if is_error:
        detail = (payload.get("stderr") or payload.get("formatted_output") or "").strip()
        prefix = f"exit {exit_code}: " if isinstance(exit_code, int) else ""
        error_text = (prefix + detail[:200]) or None

    return _ExecResult(call_id=call_id, is_error=is_error, error_text=error_text)


def _extract_patch_apply_end(payload: dict) -> _ExecResult | None:
    """Extract a ``PatchApplyEnd`` ``event_msg`` payload's real
    success/failure signal for ``apply_patch``-type calls.

    **Sprint 9 (2026-07-14), direct primary-source evidence**: fetched the
    real, current ``codex-rs/protocol/src/protocol.rs`` from
    github.com/openai/codex @ main. ``PatchApplyEndEvent`` has a
    non-optional ``call_id: String``, plain ``success: bool`` (not a status
    enum like ``ExecCommandEnd``), plus ``stdout``/``stderr``. This directly
    answers the open question Sprint 8 flagged ("what carries success for
    apply_patch") -- it's a plain boolean, no status-enum branching needed.
    """
    if not isinstance(payload, dict) or payload.get("type") != "patch_apply_end":
        return None

    call_id = payload.get("call_id")
    success = payload.get("success")
    # Real wire data always has this field (non-optional in the Rust
    # struct); missing/non-bool is malformed/test data -- don't guess failure.
    is_error = success is False

    error_text = None
    if is_error:
        detail = (payload.get("stderr") or "").strip()
        error_text = detail[:200] or None

    return _ExecResult(call_id=call_id, is_error=is_error, error_text=error_text)


def _extract_token_count(payload: dict, session_id: str | None, entry: dict) -> Action | None:
    """Extract a ``token_count`` ``event_msg`` payload into a synthetic
    Action carrying token totals.

    **PLAYBOOK Sprint 8 correction (2026-07-14), direct primary-source
    evidence**: fetched the real, current ``codex-rs/protocol/src/
    protocol.rs`` from github.com/openai/codex @ main. ``TokenCountEvent``'s
    real shape is ``{"type": "token_count", "info": {"total_token_usage":
    {...}, "last_token_usage": {...}, "model_context_window": ...},
    "rate_limits": {...}}`` -- token fields are NOT flat on the payload
    (the previous ``payload.get("input_tokens")``/``"prompt_tokens"``
    guess read a shape one level too shallow and always fell through to
    0/0) and ``TokenUsage``'s real field names are ``input_tokens``/
    ``cached_input_tokens``/``output_tokens``/``reasoning_output_tokens``/
    ``total_tokens`` -- not ``prompt_tokens``/``completion_tokens``.
    **PRD Open Question #6 resolved**: both a per-turn delta
    (``last_token_usage``) and a session-cumulative snapshot
    (``total_token_usage``) exist as separate, unambiguous fields -- this
    was never actually ambiguous on the wire, just unconfirmed. Maps
    ``last_token_usage`` (the delta) onto ``Action.tokens_in``/
    ``tokens_out``, matching the per-action-delta semantics every other
    parser in this package uses; ``total_token_usage``/
    ``model_context_window`` stay in ``raw`` for anyone wanting the
    cumulative view.
    """
    if not isinstance(payload, dict) or payload.get("type") != "token_count":
        return None

    info = payload.get("info")
    tokens_in = 0
    tokens_out = 0
    if isinstance(info, dict):
        last_usage = info.get("last_token_usage")
        if isinstance(last_usage, dict):
            tokens_in = last_usage.get("input_tokens") or 0
            tokens_out = last_usage.get("output_tokens") or 0

    return Action(
        timestamp=_parse_codex_timestamp(entry),
        tool_name="token_count",
        tool_type=ToolType.UNKNOWN,
        success=True,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        session_id=session_id,
        raw=entry,
    )


def _parse_codex_timestamp(entry: dict):
    """Parse a rollout line's top-level ``timestamp`` field.

    Local, tiny copy of ``logs.py::_parse_timestamp``'s ISO-parse-with-
    ``datetime.now()``-fallback behavior, kept independent (rather than
    imported) so this module has no module-level import of ``logs.py`` —
    ``logs.py::parse_file`` constructs a ``CodexParser`` lazily inside its
    own function body precisely to avoid a ``logs.py`` <-> ``codex.py``
    circular import; importing a private helper back from ``logs.py``
    here would reintroduce that cycle at module-import time.
    """
    from datetime import datetime

    timestamp_str = entry.get("timestamp") or entry.get("ts") or entry.get("time")
    if timestamp_str:
        try:
            parsed = datetime.fromisoformat(str(timestamp_str).replace("Z", "+00:00"))
            return parsed.replace(tzinfo=None)
        except (ValueError, AttributeError):
            pass
    return datetime.now()


class CodexParser:
    """Stateful parser for one Codex rollout JSONL stream.

    Codex correlates a tool call to its result via a shared ``call_id``
    field present on both lines, not via a parent/child event link the way
    Claude Code's assistant/user message pairing works. The two lines are
    not guaranteed adjacent (the model can emit narration between them, or
    -- per the multi-era schema risk -- future formats could reorder
    further), so calls are buffered by call_id until their matching output
    arrives, in-order, within this stream.

    One instance covers one file/stream's worth of state: construct fresh
    per file (``parse_file``) or per watched log (``LogWatcher``).
    """

    def __init__(self, session_id: str | None = None):
        self.session_id = session_id
        self._pending: dict[str, _PendingCall] = {}
        self._era: str | None = None  # set on first line seen

    def parse_line(self, entry: dict) -> list[Action]:
        if self._era is None:
            self._era = _detect_codex_era(entry)

        line_type = entry.get("type")
        payload = entry.get("payload", entry)  # era-dependent unwrap

        if line_type == "session_meta":
            if isinstance(payload, dict):
                self.session_id = (
                    payload.get("id") or payload.get("session_id") or self.session_id
                )
            return []

        if not isinstance(payload, dict):
            return []

        call = _extract_function_call(payload, era=self._era)
        if call is not None:
            action = Action(
                timestamp=_parse_codex_timestamp(entry),
                tool_name=call.name,
                tool_type=classify_codex_tool(call.name),
                success=True,  # provisional; corrected when output arrives
                file_path=call.file_path,
                command=call.command,
                tokens_in=0,
                tokens_out=0,
                cost_usd=0.0,  # Codex is subscription-billed, no per-call cost field
                session_id=self.session_id,
                raw=entry,
            )
            if not call.call_id:
                # No call_id to correlate on -- surface immediately rather
                # than buffering under a key that can never be matched.
                return [action]
            self._pending[call.call_id] = _PendingCall(action=action, call_id=call.call_id)
            return []  # not yielded yet -- wait for output to set success/error

        output = _extract_function_call_output(payload, era=self._era)
        if output is not None:
            pending = self._pending.pop(output.call_id, None) if output.call_id else None
            if pending is None:
                # Output with no matching buffered call (call seen before
                # this stream started tailing, or a schema mismatch) --
                # still surface it rather than silently dropping.
                return [
                    Action(
                        timestamp=_parse_codex_timestamp(entry),
                        tool_name="unknown_call",
                        tool_type=ToolType.UNKNOWN,
                        success=not output.is_error,
                        error_message=output.error_text,
                        session_id=self.session_id,
                        raw=entry,
                    )
                ]
            if not pending.resolved_by_event_msg:
                pending.action.success = not output.is_error
                pending.action.error_message = output.error_text
            return [pending.action]

        exec_result = _extract_exec_command_end(payload) or _extract_patch_apply_end(payload)
        if exec_result is not None:
            pending = self._pending.get(exec_result.call_id) if exec_result.call_id else None
            if pending is not None:
                # Update in place, don't pop/yield yet: function_call_output
                # (or flush() at end-of-stream, if that never arrives) is
                # still the actual yield point -- see module docstring's
                # open question on whether function_call_output always
                # follows. Marking resolved_by_event_msg protects this real
                # signal from being overwritten by function_call_output's
                # always-False guess when it does arrive later.
                pending.action.success = not exec_result.is_error
                pending.action.error_message = exec_result.error_text
                pending.resolved_by_event_msg = True
            # No matching pending call: already resolved and popped by an
            # earlier function_call_output, or this call started before the
            # watched stream began. Nothing to correlate -- don't synthesize
            # a standalone Action the way the function_call_output-orphan
            # case does, since this event alone carries no tool name.
            return []

        token_action = _extract_token_count(payload, self.session_id, entry)
        if token_action is not None:
            return [token_action]

        return []

    def flush(self) -> list[Action]:
        """Call at end-of-stream: emit any calls whose output never arrived
        (in-flight when the file ended, or an output this parser failed to
        recognize under the current era-detection).

        Only ``parse_file()``'s one-shot batch read calls this. A live
        ``LogWatcher`` tail deliberately does NOT call it -- see
        ``watcher.py``'s comment on that asymmetry.
        """
        remaining = list(self._pending.values())
        self._pending.clear()
        return [p.action for p in remaining]
