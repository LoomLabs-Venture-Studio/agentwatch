"""Registry for managing and running detectors."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import Detector, Warning, warning_dedup_key
from .health import get_all_health_detectors
from .security import get_all_security_detectors

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from agentwatch.parser.models import Action, ActionBuffer


class DetectorRegistry:
    """Registry for managing and running detectors."""

    def __init__(
        self,
        include_health: bool = True,
        include_security: bool = False,
    ):
        self.detectors: list[Detector] = []

        if include_health:
            self.detectors.extend(get_all_health_detectors())

        if include_security:
            self.detectors.extend(get_all_security_detectors())

    def add_detector(self, detector: Detector) -> None:
        """Add a custom detector to the registry."""
        self.detectors.append(detector)

    def remove_detector(self, name: str) -> bool:
        """Remove a detector by name."""
        for i, d in enumerate(self.detectors):
            if d.name == name:
                self.detectors.pop(i)
                return True
        return False

    def get_detector(self, name: str) -> Detector | None:
        """Get a detector by name."""
        for d in self.detectors:
            if d.name == name:
                return d
        return None

    def check_all(self, buffer: "ActionBuffer") -> list[Warning]:
        """Run all detectors and collect warnings."""
        warnings = []

        for detector in self.detectors:
            try:
                warning = detector.check(buffer)
                if warning:
                    warnings.append(warning)
            except Exception:
                # Don't let one detector crash everything
                pass

        # Sort by severity (critical first)
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
        }
        warnings.sort(key=lambda w: severity_order.get(w.severity.value, 4))

        return warnings

    def scan(self, actions: "Iterable[Action]", buffer: "ActionBuffer") -> list[Warning]:
        """Feed *actions* into *buffer* and return the session's warnings.

        Security detectors only look at the last 5-50 actions, so for a
        one-shot scan they run after every add, like the live TUI, and each
        distinct finding is kept once (#35), via `SessionScan`. Health
        detectors describe the current state, so they run once at the end.
        """
        session = SessionScan(self)
        for action in actions:
            session.add(buffer, action)
        return session.warnings(buffer)

    def check_health(self, buffer: "ActionBuffer") -> list[Warning]:
        """Run only health detectors."""
        warnings = []

        for detector in self.detectors:
            if not detector.is_security_detector:
                try:
                    warning = detector.check(buffer)
                    if warning:
                        warnings.append(warning)
                except Exception:
                    pass

        return warnings

    def check_security(self, buffer: "ActionBuffer") -> list[Warning]:
        """Run only security detectors. A detector with a `check_many()`
        (the secret scanner) reports every distinct finding in its window."""
        warnings = []

        for detector in self.detectors:
            if detector.is_security_detector:
                try:
                    many = getattr(detector, "check_many", None)
                    if many is not None:
                        warnings.extend(many(buffer))
                        continue
                    warning = detector.check(buffer)
                    if warning:
                        warnings.append(warning)
                except Exception:
                    pass

        return warnings

    def check_security_with_audit(
        self, buffer: "ActionBuffer"
    ) -> tuple[list[Warning], list[dict[str, Any]]]:
        """Run only security detectors via `check_with_audit()`.

        Unlike `check_security()` (which calls the plain `.check()` and
        only ever sees detectors that fired a `Warning`), this exercises
        `SecurityDetector.check_with_audit()` -- previously fully
        implemented but with zero call sites (Sprint 14 dead-code sweep) --
        to also collect one audit-log entry *per detector that ran*,
        whether it triggered or not. That's a "prove you checked"
        compliance trail, distinct from the SIEM export (`--siem-log`),
        which only ever records positive findings.

        Mirrors `check_security()`'s exception-isolation invariant: one
        detector raising must never abort the run for the others. A
        detector that raises still gets a best-effort audit entry (with
        `"error"` set) so the "did every detector run" trail doesn't
        silently drop it.

        Returns:
            (warnings, audit_logs) -- `warnings` is exactly the triggered
            subset also present (as `audit_log["warning"]`) inside the
            corresponding `audit_logs` entries.
        """
        warnings: list[Warning] = []
        audit_logs: list[dict[str, Any]] = []

        for detector in self.detectors:
            # `is_security_detector` (not `isinstance(detector,
            # SecurityDetector)`) to match the exact filtering convention
            # `check_security()`/`health_detectors`/`security_detectors`
            # already use elsewhere in this class -- a detector that sets
            # the flag without providing a real `check_with_audit()` still
            # falls into the `except` below rather than crashing the run.
            if not detector.is_security_detector:
                continue
            try:
                warning, audit_log = detector.check_with_audit(buffer)
                audit_logs.append(audit_log)
                many = getattr(detector, "check_many", None)
                if many is not None:  # every finding, as check_security() does
                    found = many(buffer)
                    audit_log["warnings"] = [w.to_dict() for w in found]
                    warnings.extend(found)
                elif warning:
                    warnings.append(warning)
            except Exception:
                audit_logs.append({
                    "detector": detector.name,
                    "category": detector.category.value,
                    "triggered": False,
                    "action_count": len(buffer),
                    "error": "detector raised an exception",
                })

        return warnings, audit_logs

    @property
    def health_detectors(self) -> list[Detector]:
        """Get all health detectors."""
        return [d for d in self.detectors if not d.is_security_detector]

    @property
    def security_detectors(self) -> list[Detector]:
        """Get all security detectors."""
        return [d for d in self.detectors if d.is_security_detector]

    def list_detectors(self) -> dict[str, list[str]]:
        """List all registered detectors by category."""
        result: dict[str, list[str]] = {}

        for detector in self.detectors:
            cat = detector.category.value
            if cat not in result:
                result[cat] = []
            result[cat].append(f"{detector.name}: {detector.description}")

        return result


def create_registry(
    mode: str = "health",
    custom_detectors: list[Detector] | None = None,
) -> DetectorRegistry:
    """
    Create a detector registry for a specific mode.

    Args:
        mode: "health", "security", or "all"
        custom_detectors: Optional list of custom detectors to add

    Returns:
        Configured DetectorRegistry
    """
    if mode == "health":
        registry = DetectorRegistry(include_health=True, include_security=False)
    elif mode == "security":
        registry = DetectorRegistry(include_health=False, include_security=True)
    elif mode == "all":
        registry = DetectorRegistry(include_health=True, include_security=True)
    else:
        raise ValueError(f"Unknown mode: {mode}")

    if custom_detectors:
        for detector in custom_detectors:
            registry.add_detector(detector)

    return registry


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# Security detectors that read a tool result's text (incoming_message,
# error_message). They need no surrounding actions, so a result that lands on
# an action already scanned is checked alone, in a scratch buffer.
_RESULT_WINDOW = 5  # the narrowest window among them (the secret scanner's)
_RESULT_DETECTORS = frozenset({"prompt_injection", "hidden_instruction", "secret_leak_scanner"})


class SessionScan:
    """One session's security findings, kept for the whole session.

    Security detectors only look at the last 5-50 actions, so a finding
    that is seen once can drop out of the window before the next check.
    `add()` feeds the buffer and runs the security detectors right away,
    keeping each finding in a ledger by `warning_dedup_key` (the higher
    severity wins if a key comes back worse). `warnings()` is the health
    detectors on the current buffer plus the ledger, after one more security
    pass on the current buffer: a detector that defers (undeclared egress
    waits for DNS) decides on a later refresh, not only when an action
    arrives. Used by `DetectorRegistry.scan` (CLI) and the live dashboard,
    so both score the same way.

    `rebind()` swaps the registry (the dashboard's security toggle) and
    keeps the ledger. While the new registry has no security detectors the
    ledger is hidden, and actions that arrive meanwhile are not scanned: on
    toggling back on (`suspend`, `plan_resume`, `replay_steps`) they are
    recovered only from the live buffer, with the older actions as context.
    """

    def __init__(self, registry: DetectorRegistry) -> None:
        self.findings: dict[str, Warning] = {}
        self._suspended_at: int | None = None
        self.version = 0  # counts changes to the ledger
        self.rebind(registry)

    def rebind(self, registry: DetectorRegistry) -> None:
        self.registry = registry
        self._has_security = any(d.is_security_detector for d in registry.detectors)
        if not self._has_security and self._suspended_at is None:
            self._suspended_at = 0  # security never ran: all of it is still to check

    @property
    def pending(self) -> bool:
        """A security detector is waiting on something (DNS) and must be
        re-run on the next refresh even without new actions."""
        return self._has_security and any(
            getattr(d, "pending", False) for d in self.registry.detectors
        )

    def _keep(self, warnings: list[Warning]) -> None:
        for w in warnings:
            key = warning_dedup_key(w)
            kept = self.findings.get(key)
            if kept is None or w.severity.score_impact > kept.severity.score_impact:
                self.findings[key] = w
                self.version += 1

    def _scan_results(self, buffer: "ActionBuffer") -> None:
        """Check the actions a tool result has landed on since the last scan.
        The window detectors may have moved past them (parallel calls)."""
        if not self._has_security:
            return
        from agentwatch.parser.models import ActionBuffer

        # Actions still in the window are re-read by the check that follows.
        in_window = {id(a) for a in buffer.last(_RESULT_WINDOW)}
        for action in buffer.take_changed():
            if id(action) in in_window:
                continue
            scratch = ActionBuffer(max_size=1)
            scratch.add(action)
            for detector in self.registry.detectors:
                if detector.name not in _RESULT_DETECTORS:
                    continue
                try:
                    many = getattr(detector, "check_many", None)
                    found = many(scratch) if many is not None else [detector.check(scratch)]
                except Exception:
                    continue
                self._keep([w for w in found if w])

    def add(self, buffer: "ActionBuffer", action: "Action") -> None:
        buffer.add(action)
        if self._has_security:
            self._scan_results(buffer)
            self._keep(self.registry.check_security(buffer))

    def suspend(self, action_count: int) -> None:
        """Security is being switched off with *action_count* actions seen.
        Everything before that point has been checked. Call before `rebind`.
        A suspend that is still waiting for its resume keeps the older mark."""
        if self._has_security and self._suspended_at is None:
            self._suspended_at = action_count

    def plan_resume(self, buffer: "ActionBuffer") -> tuple[list["Action"], list["Action"]]:
        """(context, to_check) after security is switched back on.

        Actions seen before `suspend` were already checked: they only give
        the detectors their context (a declared host, say) in the scratch
        buffer, with no check. Only the actions that arrived while security
        was off are checked. The first time security is ever on there is no
        mark, so everything the buffer holds is checked. Context older than
        the buffer cannot be recovered.
        """
        actions = list(buffer.actions)
        if self._suspended_at is None:
            return [], actions
        newer = min(max(buffer.stats.action_count - self._suspended_at, 0), len(actions))
        return actions[: len(actions) - newer], actions[len(actions) - newer :]

    def finish_resume(self) -> None:
        self._suspended_at = None

    def replay_steps(
        self,
        context: "Iterable[Action]",
        to_check: "Iterable[Action]",
        max_size: int = 500,
    ) -> "Iterator[None]":
        """Merge into the ledger the findings *to_check* would have raised,
        in a scratch buffer of *max_size* (the live buffer's capacity, so a
        detector sees the same window as it would live) that first takes
        *context* unchecked. Yields after each checked action so the caller
        can hand control back; the detectors stay on the caller's thread."""
        from agentwatch.parser.models import ActionBuffer

        scratch = ActionBuffer(max_size=max_size)
        for action in context:
            scratch.add(action)
        for action in to_check:
            self.add(scratch, action)
            yield

    def replay(self, actions: "Iterable[Action]", max_size: int = 500) -> None:
        """`replay_steps` to the end, with no context."""
        for _ in self.replay_steps((), actions, max_size):
            pass

    def warnings(self, buffer: "ActionBuffer") -> list[Warning]:
        if self._has_security:
            self._scan_results(buffer)
            self._keep(self.registry.check_security(buffer))
        warnings = self.registry.check_health(buffer)
        if self._has_security:
            warnings += self.findings.values()
        warnings.sort(key=lambda w: _SEVERITY_ORDER.get(w.severity.value, 4))
        return warnings
