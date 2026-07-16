"""Tests for `agentwatch.ui.live_integrations`: the dedup/throttle layer
that lets `--siem-log` and `--llm` be wired into the live Textual TUIs
(`AgentWatchApp`/`MultiAgentWatchApp`) without re-exporting or re-assessing
the same still-open warning on every 1s render tick.

`check_all()` (`detectors/registry.py`) constructs brand new `Warning`
objects on every call -- there is no persisted identity across ticks -- so
everything here is exercised by calling the module's functions/methods
repeatedly against *freshly constructed* `Warning` objects that merely
share the same detector signal/details, simulating what a still-open issue
looks like tick over tick.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from agentwatch.detectors.base import Category, Severity, Warning
from agentwatch.llm import LlmUnavailableError
from agentwatch.siem import SiemExportError
from agentwatch.ui.live_integrations import (
    LLM_ASSESSMENT_INTERVAL_SECONDS,
    LiveLlmAssessor,
    LiveSiemExporter,
    warning_dedup_key,
)

# ---------------------------------------------------------------------------
# warning_dedup_key
# ---------------------------------------------------------------------------


class TestWarningDedupKey:
    def test_same_signal_and_identity_details_produce_same_key(self):
        w1 = Warning(
            category=Category.ERRORS,
            severity=Severity.MEDIUM,
            signal="error_spiral",
            message="Error spiral: 3 consecutive failures",
            details={"error_class": "TypeError"},
        )
        w2 = Warning(
            category=Category.ERRORS,
            severity=Severity.MEDIUM,
            signal="error_spiral",
            message="Error spiral: 4 consecutive failures",  # counter moved on
            details={"error_class": "TypeError", "occurrences": 4},
        )
        assert warning_dedup_key(w1) == warning_dedup_key(w2)

    def test_message_counter_alone_does_not_change_key(self):
        """The whole point: a volatile counter embedded in `message` must
        not defeat dedup (see module docstring)."""
        base = dict(category=Category.PROGRESS, severity=Severity.LOW, signal="loop")
        w1 = Warning(**base, message="Re-reading file: a.py (2x)", details={"file": "a.py"})
        w2 = Warning(**base, message="Re-reading file: a.py (9x)", details={"file": "a.py"})
        assert warning_dedup_key(w1) == warning_dedup_key(w2)

    def test_different_identity_detail_produces_different_key(self):
        base = dict(category=Category.PROGRESS, severity=Severity.LOW, signal="loop", message="m")
        w1 = Warning(**base, details={"file": "a.py"})
        w2 = Warning(**base, details={"file": "b.py"})
        assert warning_dedup_key(w1) != warning_dedup_key(w2)

    def test_different_signal_produces_different_key(self):
        w1 = Warning(category=Category.ERRORS, severity=Severity.LOW, signal="stall", message="m")
        w2 = Warning(category=Category.ERRORS, severity=Severity.LOW, signal="loop", message="m")
        assert warning_dedup_key(w1) != warning_dedup_key(w2)

    def test_no_identity_details_still_stable_across_calls(self):
        """Warnings with no identifying detail fields (e.g. a singleton
        "context window full" style warning) key on signal alone -- stable
        and still correctly dedups across ticks."""
        base = dict(category=Category.CONTEXT, severity=Severity.LOW, signal="ctx_full")
        w1 = Warning(**base, message="60%")
        w2 = Warning(**base, message="75%")
        assert warning_dedup_key(w1) == warning_dedup_key(w2)


def _secret_warning(file_path="secret.env") -> Warning:
    return Warning(
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        signal="credential_access",
        message="Agent accessed sensitive path",
        details={"secret_type": "aws_key", "channel": "file_write", "file_path": file_path},
    )


# ---------------------------------------------------------------------------
# LiveSiemExporter
# ---------------------------------------------------------------------------


def _read_lines(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class TestLiveSiemExporter:
    def test_still_open_warning_exported_once_across_simulated_ticks(self, tmp_path):
        path = tmp_path / "siem.jsonl"
        exporter = LiveSiemExporter(path, source_log="agent.jsonl")

        # Tick 1, 2, 3: the "same" warning (fresh object, same dedup key)
        # reappears every tick because check_all() rebuilds it -- must
        # only be written once.
        for _ in range(3):
            err = exporter.export_new([_secret_warning()], session_id="s1")
            assert err is None

        lines = _read_lines(path)
        assert len(lines) == 1
        assert lines[0]["signal"] == "credential_access"

    def test_new_distinct_warning_is_exported(self, tmp_path):
        path = tmp_path / "siem.jsonl"
        exporter = LiveSiemExporter(path)

        exporter.export_new([_secret_warning("a.env")], session_id="s1")
        exporter.export_new([_secret_warning("a.env")], session_id="s1")  # still open, no dup
        exporter.export_new([_secret_warning("b.env")], session_id="s1")  # genuinely new

        lines = _read_lines(path)
        assert len(lines) == 2
        assert {entry["details"]["file_path"] for entry in lines} == {"a.env", "b.env"}

    def test_no_new_warnings_is_a_no_op(self, tmp_path):
        path = tmp_path / "siem.jsonl"
        exporter = LiveSiemExporter(path)
        assert exporter.export_new([]) is None
        assert not path.exists()

    def test_bad_extra_notifies_once_then_stays_quiet(self, tmp_path, monkeypatch):
        """Simulates the 'siem' extra missing (SiemExportError on first
        SiemLogger construction attempt) -- must surface exactly one error
        message across repeated ticks, not one per tick."""
        import agentwatch.ui.live_integrations as mod

        def raising_siem_logger(*args, **kwargs):
            raise SiemExportError("SIEM export requires the 'siem' extra")

        monkeypatch.setattr(mod, "SiemLogger", raising_siem_logger)

        path = tmp_path / "siem.jsonl"
        exporter = LiveSiemExporter(path)

        first = exporter.export_new([_secret_warning("a.env")])
        assert first is not None
        assert "siem" in first.lower()

        # Same still-broken path, more ticks, more (still new) warnings --
        # must not re-surface the error every time.
        second = exporter.export_new([_secret_warning("b.env")])
        third = exporter.export_new([_secret_warning("c.env")])
        assert second is None
        assert third is None

    def test_close_is_safe_when_never_constructed(self, tmp_path):
        exporter = LiveSiemExporter(tmp_path / "siem.jsonl")
        exporter.close()  # must not raise even though export_new was never called

    def test_close_releases_file_handle(self, tmp_path):
        path = tmp_path / "siem.jsonl"
        exporter = LiveSiemExporter(path)
        exporter.export_new([_secret_warning()])
        exporter.close()
        path.unlink()  # would raise PermissionError on Windows if still open
        assert not path.exists()


# ---------------------------------------------------------------------------
# LiveLlmAssessor
# ---------------------------------------------------------------------------


class _FakeOllamaClient:
    """Mirrors the real `ollama.Client` response shapes (same double used
    in test_llm.py)."""

    def __init__(self, pulled_models=("llama3.2:latest",), chat_content=None, list_raises=None):
        self._pulled_models = pulled_models
        self._chat_content = chat_content or (
            '{"likely_true_positive": true, "confidence": "high", "rationale": "Looks real."}'
        )
        self._list_raises = list_raises
        self.chat_call_count = 0

    def __call__(self, host=None):
        return self

    def list(self):
        if self._list_raises is not None:
            raise self._list_raises
        return SimpleNamespace(models=[SimpleNamespace(model=m) for m in self._pulled_models])

    def chat(self, **kwargs):
        self.chat_call_count += 1
        return SimpleNamespace(message=SimpleNamespace(content=self._chat_content))


def _patch_ollama_client(monkeypatch, fake_client):
    monkeypatch.setattr("agentwatch.llm._import_ollama_client", lambda: fake_client)


def _sample_warning(sig="credential_access", **details) -> Warning:
    return Warning(
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        signal=sig,
        message="m",
        details=details,
    )


class TestLiveLlmAssessorThrottle:
    def test_due_immediately_on_first_tick(self):
        assessor = LiveLlmAssessor(model="llama3.2")
        assert assessor.due(now=0.0) is True

    def test_not_due_again_within_interval_after_mark_run(self):
        assessor = LiveLlmAssessor(model="llama3.2")
        assessor.mark_run(now=100.0)
        assert assessor.due(now=100.0 + LLM_ASSESSMENT_INTERVAL_SECONDS - 1) is False

    def test_due_again_once_interval_elapses(self):
        assessor = LiveLlmAssessor(model="llama3.2")
        assessor.mark_run(now=100.0)
        assert assessor.due(now=100.0 + LLM_ASSESSMENT_INTERVAL_SECONDS) is True

    def test_not_due_while_a_batch_is_in_flight(self):
        assessor = LiveLlmAssessor(model="llama3.2")
        assessor._running = True
        assert assessor.due(now=10_000.0) is False

    def test_not_due_once_confirmed_unavailable(self, monkeypatch):
        fake = _FakeOllamaClient(list_raises=ConnectionError("refused"))
        _patch_ollama_client(monkeypatch, fake)
        assessor = LiveLlmAssessor(model="llama3.2")
        assessor.run_batch([_sample_warning()])
        assert assessor.due(now=1_000_000.0) is False


class TestLiveLlmAssessorDedup:
    def test_new_warnings_excludes_already_assessed(self, monkeypatch):
        fake = _FakeOllamaClient()
        _patch_ollama_client(monkeypatch, fake)
        assessor = LiveLlmAssessor(model="llama3.2")

        w = _sample_warning(path="x.py")
        assessor.run_batch([w])
        assert assessor.new_warnings([w]) == []  # already assessed, same dedup key

        w_other = _sample_warning(path="y.py")
        assert assessor.new_warnings([w, w_other]) == [w_other]

    def test_run_batch_skips_already_assessed_without_extra_chat_calls(self, monkeypatch):
        fake = _FakeOllamaClient()
        _patch_ollama_client(monkeypatch, fake)
        assessor = LiveLlmAssessor(model="llama3.2")

        w = _sample_warning(path="x.py")
        assessor.run_batch([w])
        assert fake.chat_call_count == 1

        # Same dedup key reappears (new object, simulated next tick) --
        # must not be re-submitted to the local model.
        w_again = _sample_warning(path="x.py")
        assessor.run_batch([w_again])
        assert fake.chat_call_count == 1

    def test_respects_max_warnings_to_assess_cap(self, monkeypatch):
        from agentwatch.llm import MAX_WARNINGS_TO_ASSESS

        fake = _FakeOllamaClient()
        _patch_ollama_client(monkeypatch, fake)
        assessor = LiveLlmAssessor(model="llama3.2")

        warnings = [_sample_warning(path=f"f{i}.py") for i in range(MAX_WARNINGS_TO_ASSESS + 5)]
        assessor.run_batch(warnings)
        assert fake.chat_call_count == MAX_WARNINGS_TO_ASSESS


class TestLiveLlmAssessorStamp:
    def test_stamp_reattaches_cached_assessment_across_simulated_ticks(self, monkeypatch):
        fake = _FakeOllamaClient(
            chat_content='{"likely_true_positive": false, "confidence": "medium", '
            '"rationale": "Probably benign."}'
        )
        _patch_ollama_client(monkeypatch, fake)
        assessor = LiveLlmAssessor(model="llama3.2")

        w = _sample_warning(path="x.py")
        assessor.run_batch([w])

        # Next tick: check_all() built an entirely new Warning object with
        # no "llm_assessment" in .details -- stamp() must restore it.
        w_next_tick = _sample_warning(path="x.py")
        assert "llm_assessment" not in w_next_tick.details
        assessor.stamp([w_next_tick])
        assert w_next_tick.details["llm_assessment"]["likely_true_positive"] is False
        assert w_next_tick.details["llm_assessment"]["confidence"] == "medium"

    def test_stamp_is_no_op_for_unassessed_warning(self):
        assessor = LiveLlmAssessor(model="llama3.2")
        w = _sample_warning(path="never-assessed.py")
        assessor.stamp([w])
        assert "llm_assessment" not in w.details


class TestLiveLlmAssessorUnavailable:
    def test_run_batch_returns_message_first_time_unavailable(self, monkeypatch):
        fake = _FakeOllamaClient(list_raises=ConnectionError("refused"))
        _patch_ollama_client(monkeypatch, fake)
        assessor = LiveLlmAssessor(model="llama3.2")

        error = assessor.run_batch([_sample_warning()])
        assert error is not None
        assert "ollama serve" in error

    def test_run_batch_stays_quiet_on_subsequent_calls(self, monkeypatch):
        """Ollama-down must notify once, not spam every throttled attempt."""
        fake = _FakeOllamaClient(list_raises=ConnectionError("refused"))
        _patch_ollama_client(monkeypatch, fake)
        assessor = LiveLlmAssessor(model="llama3.2")

        first = assessor.run_batch([_sample_warning()])
        second = assessor.run_batch([_sample_warning()])
        third = assessor.run_batch([_sample_warning()])
        assert first is not None
        assert second is None
        assert third is None

    def test_missing_llm_extra_surfaces_as_unavailable(self, monkeypatch):
        def fake_import():
            raise LlmUnavailableError(
                "Tier-2 LLM analysis requires the 'llm' extra: "
                'pip install "agentwatch-monitor[llm]"'
            )

        monkeypatch.setattr("agentwatch.llm._import_ollama_client", fake_import)
        assessor = LiveLlmAssessor(model="llama3.2")
        error = assessor.run_batch([_sample_warning()])
        assert error is not None
        assert "llm" in error.lower()
