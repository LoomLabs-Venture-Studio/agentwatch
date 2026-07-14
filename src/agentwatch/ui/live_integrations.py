"""Shared live-TUI wiring for `--siem-log` export and `--llm` Tier-2 triage.

`AgentWatchApp` (`ui/app.py`, single-agent) and `MultiAgentWatchApp`
(`ui/multi_app.py`, one of these per tracked agent) both re-run
`registry.check_all()` on a 1s `set_interval` render tick. `Warning` is a
plain `@dataclass` (`detectors/base.py`) freshly constructed by whichever
detector fires on *every* `check_all()` call (`detectors/registry.py`) --
there is no persisted object identity to key off of tick-over-tick, so a
still-open issue is a brand new `Warning` instance every second.

That has two consequences this module exists to handle:

1. **SIEM export** must not re-append the same still-open warning every
   tick (log spam, and not how a real event stream behaves -- a
   still-open event is logged once, not re-emitted every second). We need
   a content-based "have I already exported this" key.
2. **Tier-2 LLM assessment** (`llm.py`'s `OllamaAnalyzer.assess_warning`)
   is a real local HTTP round-trip. Calling it once per still-open warning
   per second would hammer the local Ollama daemon continuously and, if
   ever called synchronously, stall the render loop. It needs both a
   coarser cadence than 1s and to run off the render path.

`warning_dedup_key()` is the content-based identity substitute. It
deliberately does NOT use `warning.message`: several detectors embed a
live counter directly in the message (e.g. `errors.py`'s "Error spiral: 4
consecutive failures" -> "5 consecutive failures" as more turns arrive),
which would change every tick and defeat dedup entirely. Instead it keys
on `signal` plus whichever "identity-ish" detail fields are present
(file/path/error-class/...), mirroring the dedup key `ui/app.py`'s
`_fire_secret_alerts` already uses for its secret-leak toast
notifications -- this module generalizes that same pattern rather than
inventing a new one.
"""

from __future__ import annotations

# Bound as a private module-level name (not `import time` + `time.monotonic()`)
# specifically so tests can `monkeypatch.setattr(module, "_monotonic", fake)`
# to control the throttle clock deterministically -- patching `time.monotonic`
# itself would mutate the actual shared stdlib `time` module for the whole
# process, including asyncio's/Textual's own internal scheduling, which
# hangs the event loop rather than just faking this module's clock.
from time import monotonic as _monotonic
from typing import TYPE_CHECKING

from agentwatch.llm import MAX_WARNINGS_TO_ASSESS, LlmUnavailableError, OllamaAnalyzer
from agentwatch.siem import SiemExportError, SiemLogger

if TYPE_CHECKING:
    from pathlib import Path

    from agentwatch.detectors.base import Warning

# A local Ollama chat call per warning is a real HTTP round-trip (typically
# well over a second for a small model). Running that on the 1s
# health-refresh tick would hammer the daemon continuously for as long as
# a warning stays open, and would visibly stall the UI if it were ever run
# synchronously on the render path (it isn't -- see LiveLlmAssessor.run_batch,
# always invoked via asyncio.to_thread from a Textual worker). 30s is a
# materially coarser cadence than the 1s render tick while still refreshing
# several times over a typical multi-minute agent session.
LLM_ASSESSMENT_INTERVAL_SECONDS = 30.0

# "Identity-ish" detail keys, checked in this order, used to disambiguate
# two simultaneously-open warnings that share the same `signal` but concern
# different targets (e.g. two different files each independently tripping
# the same re-read-loop detector). Deliberately excludes any key known to
# carry a live occurrence counter (those change every tick and would defeat
# dedup if included here).
_IDENTITY_DETAIL_KEYS = (
    "secret_type",
    "channel",
    "file_path",
    "file",
    "path",
    "error_class",
    "error_pattern",
    "last_command",
    "last_error",
)


def warning_dedup_key(warning: "Warning") -> str:
    """Stable content-based identity for *warning*, used to recognize
    "already seen, still open" across `check_all()` calls that construct
    an entirely new `Warning` object each time."""
    parts = [warning.signal]
    for key in _IDENTITY_DETAIL_KEYS:
        value = warning.details.get(key)
        if value:
            parts.append(f"{key}={value}")
    return "|".join(parts)


class LiveSiemExporter:
    """Appends only newly-seen warnings (by `warning_dedup_key`) to a SIEM
    JSON-lines log across repeated `export_new()` calls -- one export per
    distinct finding, not a re-dump on every tick, matching real SIEM/
    event-stream semantics (log new events as they appear).

    One instance per agent being watched (a single `AgentWatchApp` owns
    one; a `MultiAgentWatchApp` owns one per tracked agent, so each
    agent's findings export independently under its own identity).
    """

    def __init__(
        self,
        path: "Path",
        *,
        agent_type: str | None = None,
        source_log: str | None = None,
    ) -> None:
        self._path = path
        self._agent_type = agent_type
        self._source_log = source_log
        self._logger: SiemLogger | None = None
        self._exported_keys: set[str] = set()
        self._error_notified = False

    def export_new(
        self, warnings: list["Warning"], *, session_id: str | None = None
    ) -> str | None:
        """Append any not-yet-exported warnings from *warnings*.

        Returns an error message the FIRST time export fails (bad path,
        missing `siem` extra, ...) so the caller can surface exactly one
        notification; returns `None` on success and on every subsequent
        failure after the first (already surfaced -- must not spam a
        notification every tick for a persistently broken path).
        """
        new_warnings = [w for w in warnings if warning_dedup_key(w) not in self._exported_keys]
        if not new_warnings:
            return None
        try:
            if self._logger is None:
                self._logger = SiemLogger(
                    self._path,
                    agent_type=self._agent_type,
                    session_id=session_id,
                    source_log=self._source_log,
                )
            for w in new_warnings:
                self._logger.log_warning(w)
                self._exported_keys.add(warning_dedup_key(w))
            return None
        except (SiemExportError, OSError) as exc:
            if self._error_notified:
                return None
            self._error_notified = True
            return str(exc)

    def close(self) -> None:
        if self._logger is not None:
            self._logger.close()


class LiveLlmAssessor:
    """Throttled, worker-friendly Tier-2 triage for one agent's warning
    stream.

    Split into a cheap render-tick half (`due()` / `new_warnings()` /
    `stamp()`, safe to call every 1s tick) and a blocking half
    (`run_batch()`, meant to be called via `asyncio.to_thread` from a
    Textual `run_worker` so the real Ollama HTTP round-trips never run on
    the render path).
    """

    def __init__(self, model: str) -> None:
        self._model = model
        self._analyzer: OllamaAnalyzer | None = None
        self._available: bool | None = None
        self._assessed_keys: set[str] = set()
        self._assessments: dict[str, dict] = {}
        # Negative offset so the very first render tick after mount is
        # already eligible, instead of waiting a full interval before the
        # first Tier-2 attempt.
        self._last_run: float = -LLM_ASSESSMENT_INTERVAL_SECONDS
        self._unavailable_notified = False
        self._running = False

    def due(self, now: float | None = None) -> bool:
        """Whether a new assessment batch should be dispatched now.

        `False` once Ollama has been confirmed unavailable (no point
        retrying every interval and re-hammering a daemon that isn't
        there) or while a previous batch is still in flight (throttle is
        about dispatch cadence, not about racing two batches at once)."""
        if self._available is False or self._running:
            return False
        now = _monotonic() if now is None else now
        return (now - self._last_run) >= LLM_ASSESSMENT_INTERVAL_SECONDS

    def new_warnings(self, warnings: list["Warning"]) -> list["Warning"]:
        """Warnings from *warnings* not yet assessed (by dedup key)."""
        return [w for w in warnings if warning_dedup_key(w) not in self._assessed_keys]

    def mark_run(self, now: float | None = None) -> None:
        """Record that a batch was just dispatched, resetting the throttle
        window. Called at dispatch time (not completion time) so a slow
        batch doesn't cause back-to-back dispatches once it finishes."""
        self._last_run = _monotonic() if now is None else now

    def stamp(self, warnings: list["Warning"]) -> None:
        """Attach any previously-cached assessment back onto this tick's
        freshly-constructed `Warning` objects (which don't persist
        identity across ticks) so an already-assessed finding keeps
        showing its Tier-2 verdict on every subsequent render."""
        for w in warnings:
            cached = self._assessments.get(warning_dedup_key(w))
            if cached is not None:
                w.details["llm_assessment"] = cached

    def run_batch(self, warnings: list["Warning"]) -> str | None:
        """Blocking -- call via `asyncio.to_thread`, never directly on the
        event loop / render path.

        Establishes Ollama availability once (cached thereafter) and
        assesses up to `MAX_WARNINGS_TO_ASSESS` of *warnings*. Returns an
        unavailable-error message the FIRST time Ollama can't be reached
        (so the caller can surface exactly one notification), `None`
        otherwise -- including on every later call after already-notified,
        so an Ollama-down daemon doesn't spam a notification every 30s.
        """
        self._running = True
        try:
            if self._analyzer is None:
                try:
                    analyzer = OllamaAnalyzer(model=self._model)
                    analyzer.check_available()
                except LlmUnavailableError as exc:
                    self._available = False
                    if self._unavailable_notified:
                        return None
                    self._unavailable_notified = True
                    return str(exc)
                self._analyzer = analyzer
                self._available = True

            assessed = 0
            for w in warnings:
                if assessed >= MAX_WARNINGS_TO_ASSESS:
                    break
                key = warning_dedup_key(w)
                if key in self._assessed_keys:
                    continue
                try:
                    assessment = self._analyzer.assess_warning(w)
                except Exception:
                    continue
                self._assessments[key] = assessment.to_dict()
                self._assessed_keys.add(key)
                assessed += 1
            return None
        finally:
            self._running = False
