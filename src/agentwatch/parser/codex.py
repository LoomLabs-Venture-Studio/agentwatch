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

**Fixture-based implementation, not verified against a live Codex CLI
install** (see `PLAYBOOK.md` Sprint 4 and
``codex-cli-support-prd.md``'s "Open Questions / Requires Live Install to
Confirm" section). The single highest-priority unconfirmed assumption (Open
Question #1) is that ``response_item`` lines nest as
``{"type": "response_item", "payload": {"type": "function_call", ...}}``
(two-level nesting) rather than a flat compound ``type`` string. All of the
era-detection and field-extraction logic below is written to be patchable
in isolation once a real captured rollout file is available — it does not
leak the nested-shape assumption outside this module.
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
class _PendingCall:
    """A function_call seen but not yet matched to its output."""

    action: Action
    call_id: str


def classify_codex_tool(name: str) -> ToolType:
    """Classify a Codex function-call name into a ToolType.

    Reuses ``logs.classify_tool``'s substring rules as the base case —
    Codex's real tool names are unconfirmed (PRD Open Question #3), but
    likely follow similar shell/exec/read/write vocabulary based on
    OpenAI's public function-calling conventions. Adds one Codex-specific
    name pattern (``apply_patch``, Codex's documented file-edit mechanism)
    -> EDIT.

    Treat this as a conservative stub, not a finished mapping: until real
    tool names are captured and confirmed, expect most/all Codex actions
    to classify as ``ToolType.UNKNOWN`` — that is documented, expected
    behavior for this sprint, not a bug.
    """
    name_lower = name.lower()
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
    """
    del era  # reserved for future per-era divergence
    if not isinstance(payload, dict) or payload.get("type") != "function_call_output":
        return None

    call_id = payload.get("call_id") or payload.get("id")
    output = _coerce_json(payload.get("output"))

    is_error = False
    error_text = None
    if isinstance(output, dict):
        is_error = output.get("success") is False or bool(output.get("error"))
        if is_error:
            error_text = output.get("error") or output.get("content")
            if error_text is not None:
                error_text = str(error_text)[:500]

    return _FunctionCallOutput(call_id=call_id, is_error=is_error, error_text=error_text)


def _extract_token_count(payload: dict, session_id: str | None, entry: dict) -> Action | None:
    """Extract a ``token_count`` ``event_msg`` payload into a synthetic
    Action carrying token totals.

    Whether these are per-call deltas or session-cumulative snapshots is
    unconfirmed (PRD Open Question #6) — this treats them as per-action
    values without commitment, matching the PRD's stub.
    """
    if not isinstance(payload, dict) or payload.get("type") != "token_count":
        return None

    tokens_in = payload.get("input_tokens") or payload.get("prompt_tokens") or 0
    tokens_out = payload.get("output_tokens") or payload.get("completion_tokens") or 0

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
            pending.action.success = not output.is_error
            pending.action.error_message = output.error_text
            return [pending.action]

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
