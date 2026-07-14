"""Structured JSON-lines export for downstream SIEM ingestion.

Writes one JSON object per line to a caller-specified file, using
`python-json-logger` (the optional `siem` extra: `pip install
"agentwatch-monitor[siem]"`). This deliberately does not target or know
about any specific SIEM product (Splunk, Elastic, Datadog, ...) -- a
JSON-lines file is the standard hand-off point every log-forwarding agent
already knows how to tail and parse, so agentwatch's job stops at
producing clean structured output, not at owning the transport.

Import path note: `python-json-logger` restructured its module layout in
the 2.0.7 release, moving the real (non-deprecated) `JsonFormatter` from
`pythonjsonlogger.jsonlogger` to `pythonjsonlogger.json`. `pyproject.toml`
pins `python-json-logger>=2.0.0` with no upper bound, so a fresh install
gets the new path (confirmed against the real 4.1.0 package on PyPI as of
this writing), but the >=2.0.0 floor technically allows an older 2.0.x
release that predates the split. Both import paths are tried so this
works either way rather than assuming the newest layout.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .detectors.base import Severity

if TYPE_CHECKING:
    from .detectors.base import Warning

_SEVERITY_TO_LOG_LEVEL = {
    Severity.LOW: logging.INFO,
    Severity.MEDIUM: logging.WARNING,
    Severity.HIGH: logging.ERROR,
    Severity.CRITICAL: logging.CRITICAL,
}


class SiemExportError(RuntimeError):
    """Raised when SIEM export is requested but the `siem` extra isn't installed."""


def _import_json_formatter():
    try:
        from pythonjsonlogger.json import JsonFormatter

        return JsonFormatter
    except ImportError:
        pass
    try:
        from pythonjsonlogger.jsonlogger import JsonFormatter

        return JsonFormatter
    except ImportError as exc:
        raise SiemExportError(
            "SIEM export requires the 'siem' extra: "
            'pip install "agentwatch-monitor[siem]"'
        ) from exc


class SiemLogger:
    """Appends one JSON object per `Warning` to a JSON-lines file.

    One instance owns one open file handle; call `close()` when done
    (or use as a context manager) to flush and release it. Safe to point
    multiple runs at the same path -- opens in append mode, matching how
    every real log-forwarding agent expects a log file to behave.
    """

    def __init__(
        self,
        path: Path,
        *,
        agent_type: str | None = None,
        session_id: str | None = None,
        source_log: str | None = None,
    ) -> None:
        json_formatter_cls = _import_json_formatter()

        self.path = Path(path)
        self._agent_type = agent_type
        self._session_id = session_id
        self._source_log = source_log

        # A dedicated, non-propagating logger per instance (keyed by the
        # resolved absolute path) so this never collides with the root
        # logger or another SiemLogger instance's handlers, and so
        # repeated construction against the same path in one process
        # doesn't accumulate duplicate handlers.
        logger_name = f"agentwatch.siem.{self.path.resolve()}"
        self._logger = logging.getLogger(logger_name)
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        for handler in list(self._logger.handlers):
            handler.close()
            self._logger.removeHandler(handler)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(self.path, mode="a", encoding="utf-8")
        handler.setFormatter(
            # `fmt` controls which LogRecord attributes are extracted at all
            # (JsonFormatter's field set is NOT "everything on the record"
            # by default -- confirmed live: omitting %(levelname)s here
            # silently drops severity from every output line). `message` is
            # always included regardless of fmt.
            json_formatter_cls(
                "%(levelname)s %(message)s",
                rename_fields={"levelname": "severity"},
                timestamp=True,
            )
        )
        self._logger.addHandler(handler)
        self._handler = handler

    def log_warning(self, warning: "Warning") -> None:
        """Append one JSON line for *warning*."""
        payload: dict[str, Any] = {
            "event_type": "agentwatch.warning",
            "category": warning.category.value,
            "signal": warning.signal,
            "is_security": warning.is_security,
            "agent_type": self._agent_type,
            "session_id": self._session_id,
            "source_log": self._source_log,
            "details": warning.details,
        }
        if warning.suggestion:
            payload["suggestion"] = warning.suggestion
        # warning.severity drives the "severity" field via the rename_fields
        # mapping above (levelname -> severity), set from the log level.
        self._logger.log(_SEVERITY_TO_LOG_LEVEL[warning.severity], warning.message, extra=payload)

    def log_report_summary(self, report_type: str, score: float, warning_count: int) -> None:
        """Append one summary line for a completed `check`/`security-scan` run."""
        self._logger.info(
            f"{report_type} report: score={score} warnings={warning_count}",
            extra={
                "event_type": "agentwatch.report_summary",
                "report_type": report_type,
                "score": score,
                "warning_count": warning_count,
                "agent_type": self._agent_type,
                "session_id": self._session_id,
                "source_log": self._source_log,
            },
        )

    def close(self) -> None:
        self._handler.close()
        self._logger.removeHandler(self._handler)

    def __enter__(self) -> "SiemLogger":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
