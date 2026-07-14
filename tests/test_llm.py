"""Tests for `agentwatch.llm`: Tier-2 opt-in semantic analysis via a local
Ollama model (the "what other features are left" follow-up, 2026-07-14).

Everything here drives `OllamaAnalyzer` against a fake Ollama `Client`
double (`_FakeOllamaClient`), not a live Ollama daemon -- no live install
exists to test against on this machine, matching the project's existing
convention of clearly labeling fixture-only coverage (see
`test_codex_parser.py`'s module docstring for the precedent). Response
shapes (`.list()` -> `models: [Model(model=...)]`, `.chat()` ->
`ChatResponse(message=Message(content=...))`) are modeled directly on the
real `ollama` package's `_types.py` (installed via the `llm` extra in this
dev environment), not guessed.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.llm import LlmUnavailableError, OllamaAnalyzer

# ---------------------------------------------------------------------------
# Fake Ollama client -- mirrors the real SDK's response shapes.
# ---------------------------------------------------------------------------


class _FakeOllamaClient:
    """Records the last chat() call and returns configurable responses."""

    def __init__(
        self,
        pulled_models=("llama3.2:latest",),
        chat_content='{"likely_true_positive": true, "confidence": "high", '
        '"rationale": "Looks real."}',
        list_raises=None,
    ):
        self._pulled_models = pulled_models
        self._chat_content = chat_content
        self._list_raises = list_raises
        self.last_chat_kwargs = None

    def __call__(self, host=None):
        self.host = host
        return self

    def list(self):
        if self._list_raises is not None:
            raise self._list_raises
        return SimpleNamespace(models=[SimpleNamespace(model=m) for m in self._pulled_models])

    def chat(self, **kwargs):
        self.last_chat_kwargs = kwargs
        return SimpleNamespace(message=SimpleNamespace(content=self._chat_content))


def _make_analyzer(monkeypatch, **fake_client_kwargs) -> tuple[OllamaAnalyzer, _FakeOllamaClient]:
    fake_client_instance = _FakeOllamaClient(**fake_client_kwargs)

    def fake_import():
        return fake_client_instance

    monkeypatch.setattr("agentwatch.llm._import_ollama_client", fake_import)
    analyzer = OllamaAnalyzer(model="llama3.2")
    return analyzer, fake_client_instance


def _sample_warning(**overrides) -> Warning:
    defaults = dict(
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        signal="credential_access",
        message="Agent accessed sensitive path: .env",
        details={"path": ".env", "operation": "read"},
    )
    defaults.update(overrides)
    return Warning(**defaults)


# ---------------------------------------------------------------------------
# check_available
# ---------------------------------------------------------------------------


class TestCheckAvailable:
    def test_passes_when_model_pulled_exact_match(self, monkeypatch):
        analyzer, _ = _make_analyzer(monkeypatch, pulled_models=("llama3.2",))
        analyzer.check_available()  # must not raise

    def test_passes_when_model_pulled_with_tag_suffix(self, monkeypatch):
        """User asks for "llama3.2"; Ollama reports it pulled as
        "llama3.2:latest" -- must match on the bare name."""
        analyzer, _ = _make_analyzer(monkeypatch, pulled_models=("llama3.2:latest",))
        analyzer.check_available()  # must not raise

    def test_raises_when_model_not_pulled(self, monkeypatch):
        analyzer, _ = _make_analyzer(monkeypatch, pulled_models=("mistral:latest",))
        with pytest.raises(LlmUnavailableError, match="ollama pull llama3.2"):
            analyzer.check_available()

    def test_raises_with_actionable_message_when_daemon_unreachable(self, monkeypatch):
        analyzer, _ = _make_analyzer(
            monkeypatch, list_raises=ConnectionError("Connection refused")
        )
        with pytest.raises(LlmUnavailableError, match="ollama serve"):
            analyzer.check_available()


# ---------------------------------------------------------------------------
# assess_warning
# ---------------------------------------------------------------------------


class TestAssessWarning:
    def test_parses_clean_json_response(self, monkeypatch):
        analyzer, fake = _make_analyzer(
            monkeypatch,
            chat_content='{"likely_true_positive": true, "confidence": "high", '
            '"rationale": "Real credential access."}',
        )
        result = analyzer.assess_warning(_sample_warning())
        assert result.likely_true_positive is True
        assert result.confidence == "high"
        assert result.rationale == "Real credential access."

    def test_sends_model_and_temperature_zero(self, monkeypatch):
        analyzer, fake = _make_analyzer(monkeypatch)
        analyzer.assess_warning(_sample_warning())
        assert fake.last_chat_kwargs["model"] == "llama3.2"
        assert fake.last_chat_kwargs["options"]["temperature"] == 0.0
        assert fake.last_chat_kwargs["format"] == "json"

    def test_prompt_includes_warning_fields(self, monkeypatch):
        analyzer, fake = _make_analyzer(monkeypatch)
        analyzer.assess_warning(_sample_warning())
        prompt = fake.last_chat_kwargs["messages"][0]["content"]
        assert "credential_access" in prompt
        assert "Agent accessed sensitive path: .env" in prompt

    def test_salvages_json_embedded_in_prose(self, monkeypatch):
        """Small local models don't always obey format=json perfectly."""
        analyzer, _ = _make_analyzer(
            monkeypatch,
            chat_content="Sure, here is my answer: "
            '{"likely_true_positive": false, "confidence": "medium", '
            '"rationale": "Looks benign."} Hope that helps!',
        )
        result = analyzer.assess_warning(_sample_warning())
        assert result.likely_true_positive is False
        assert result.confidence == "medium"

    def test_unparseable_response_returns_none_not_crash(self, monkeypatch):
        analyzer, _ = _make_analyzer(monkeypatch, chat_content="I cannot help with that.")
        result = analyzer.assess_warning(_sample_warning())
        assert result.likely_true_positive is None
        assert result.confidence == "low"
        assert result.raw_response == "I cannot help with that."

    def test_invalid_confidence_value_defaults_to_low(self, monkeypatch):
        analyzer, _ = _make_analyzer(
            monkeypatch,
            chat_content='{"likely_true_positive": true, '
            '"confidence": "extremely-sure", "rationale": "x"}',
        )
        result = analyzer.assess_warning(_sample_warning())
        assert result.confidence == "low"

    def test_non_bool_likely_true_positive_becomes_none(self, monkeypatch):
        analyzer, _ = _make_analyzer(
            monkeypatch,
            chat_content='{"likely_true_positive": "yes", "confidence": "high", "rationale": "x"}',
        )
        result = analyzer.assess_warning(_sample_warning())
        assert result.likely_true_positive is None

    def test_to_dict_shape(self, monkeypatch):
        analyzer, _ = _make_analyzer(monkeypatch)
        result = analyzer.assess_warning(_sample_warning())
        d = result.to_dict()
        assert set(d.keys()) == {"likely_true_positive", "confidence", "rationale"}


# ---------------------------------------------------------------------------
# Missing 'llm' extra
# ---------------------------------------------------------------------------


class TestMissingLlmExtra:
    def test_raises_llm_unavailable_error_when_ollama_not_installed(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "ollama":
                raise ImportError("simulated: llm extra not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(LlmUnavailableError, match="llm"):
            OllamaAnalyzer()
