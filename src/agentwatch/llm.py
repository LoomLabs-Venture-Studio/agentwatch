"""Tier-2 opt-in semantic analysis via a local Ollama model.

README's architecture diagram has always described a two-tier model:

    TIER 1: Deterministic Detectors (always on)
    TIER 2: LLM Analysis (opt-in) -- Local model (Ollama) or cheap API (Haiku)

Tier 1 (every detector in `detectors/`) stays exactly as-is: deterministic,
auditable, zero-cost, and the sole driver of the health/security *score*.
Tier 2 is additive triage, not a replacement -- it never changes a score or
a severity, it only attaches an advisory assessment (`Warning.details
["llm_assessment"]`) to warnings Tier 1 already found, to help a human
judge which ones are worth their attention first.

**Local-only, by explicit product decision, not an oversight**: this
project's own security detectors exist partly to catch credential leaks
and secrets *in agent logs*. Sending that same log content to an external
API (the README diagram's other option, "cheap API (Haiku)") would be in
direct tension with that purpose, so Tier 2 only ever talks to a local
Ollama daemon -- nothing here makes a network call to any external host,
and there is no API-key env var to configure.

**Degrades gracefully, not silently**: if Ollama isn't running or the
requested model isn't pulled, `OllamaAnalyzer.check_available()` raises
`LlmUnavailableError` with a specific, actionable message. CLI callers are
expected to catch it, print a clear one-line warning, and continue with
Tier-1-only results -- Tier 2 being unavailable must never fail a
`check`/`security-scan` run outright, matching the "opt-in enrichment"
framing above.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .detectors.base import Warning

DEFAULT_OLLAMA_MODEL = "llama3.2"

# Small local models don't reliably keep triage latency low across a long
# warning list; capping keeps `--llm` runs bounded rather than silently
# turning a fast scan into a multi-minute one.
MAX_WARNINGS_TO_ASSESS = 10

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


class LlmUnavailableError(RuntimeError):
    """Raised when Tier-2 analysis is requested but the local Ollama
    daemon isn't reachable, or the requested model isn't pulled."""


def _import_ollama_client():
    try:
        from ollama import Client

        return Client
    except ImportError as exc:
        raise LlmUnavailableError(
            "Tier-2 LLM analysis requires the 'llm' extra: "
            'pip install "agentwatch-monitor[llm]"'
        ) from exc


@dataclass
class LlmAssessment:
    """One warning's Tier-2 triage result.

    `likely_true_positive`/`confidence`/`rationale` are the model's own
    self-reported judgment -- not independently calibrated or verified, and
    should be presented to a human as a second opinion, not a verdict.
    `likely_true_positive` is `None` when the model's response couldn't be
    parsed into a usable answer at all (still surfaced, not hidden, so a
    caller can tell "assessed but unclear" apart from "not assessed").
    """

    likely_true_positive: bool | None
    confidence: str  # "low" | "medium" | "high"
    rationale: str
    raw_response: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "likely_true_positive": self.likely_true_positive,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }


class OllamaAnalyzer:
    """Wraps a local Ollama chat model for Tier-2 warning triage.

    One instance per `model`/`host`; construct once per CLI invocation and
    call `check_available()` once up front (fail-fast with a clear message)
    before looping `assess_warning()` over a warning list.
    """

    def __init__(self, model: str = DEFAULT_OLLAMA_MODEL, host: str | None = None) -> None:
        client_cls = _import_ollama_client()
        self.model = model
        self._client = client_cls(host=host)

    def check_available(self) -> None:
        """Raise `LlmUnavailableError` with a specific, actionable message
        if the local Ollama daemon isn't reachable or `self.model` isn't
        pulled. Deliberately catches any exception from the connection
        attempt (connection-refused, DNS failure, timeout, ...) and
        converts it to one clear message rather than letting a raw
        transport-level traceback surface mid-scan."""
        try:
            response = self._client.list()
        except Exception as exc:
            raise LlmUnavailableError(
                f"Could not reach a local Ollama server -- is `ollama serve` running? "
                f"({exc})"
            ) from exc

        pulled_names = {m.model for m in response.models if m.model}
        # Ollama model names carry a ":tag" suffix (e.g. "llama3.2:latest").
        # Match on the bare name too so a user-supplied "llama3.2" matches a
        # pulled "llama3.2:latest" without requiring an exact tag match.
        bare_pulled_names = {name.split(":")[0] for name in pulled_names}
        if self.model not in pulled_names and self.model.split(":")[0] not in bare_pulled_names:
            raise LlmUnavailableError(
                f"Model '{self.model}' is not pulled locally. Run: ollama pull {self.model}"
            )

    def assess_warning(self, warning: "Warning") -> LlmAssessment:
        """Ask the local model to triage one Tier-1 `Warning`."""
        prompt = self._build_prompt(warning)
        response = self._client.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            format="json",
            options={"temperature": 0.0},
        )
        content = response.message.content or ""
        return self._parse_response(content)

    @staticmethod
    def _build_prompt(warning: "Warning") -> str:
        return (
            "You are a security triage assistant reviewing one automated "
            "finding from a deterministic pattern-matching detector that "
            "monitors an AI coding agent's session log. Judge whether this "
            "looks like a genuine issue or a likely false positive, and "
            "give a one or two sentence reason.\n\n"
            f"Detector category: {warning.category.value}\n"
            f"Detector signal: {warning.signal}\n"
            f"Detector message: {warning.message}\n"
            f"Detector details: {warning.details}\n\n"
            "Respond with ONLY a JSON object of this exact shape, no other "
            "text: "
            '{"likely_true_positive": true or false, '
            '"confidence": "low" or "medium" or "high", '
            '"rationale": "<one or two sentences>"}'
        )

    @staticmethod
    def _parse_response(content: str) -> LlmAssessment:
        data = None
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            # Small local models don't always obey format="json" perfectly
            # (extra prose before/after the object) -- salvage the first
            # {...} block rather than giving up outright.
            match = _JSON_OBJECT_RE.search(content)
            if match:
                try:
                    data = json.loads(match.group(0))
                except json.JSONDecodeError:
                    data = None

        if not isinstance(data, dict):
            return LlmAssessment(
                likely_true_positive=None,
                confidence="low",
                rationale="Model response could not be parsed.",
                raw_response=content,
            )

        likely_true_positive = data.get("likely_true_positive")
        if not isinstance(likely_true_positive, bool):
            likely_true_positive = None

        confidence = data.get("confidence")
        if confidence not in ("low", "medium", "high"):
            confidence = "low"

        rationale = data.get("rationale")
        if not isinstance(rationale, str):
            rationale = ""

        return LlmAssessment(
            likely_true_positive=likely_true_positive,
            confidence=confidence,
            rationale=rationale,
            raw_response=content,
        )
