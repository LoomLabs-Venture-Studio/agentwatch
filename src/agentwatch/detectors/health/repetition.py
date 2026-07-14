"""Module B: Repetition / self-looping metrics (deterministic)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from agentwatch.parser.models import MetricResult, Turn, turns_from_buffer
from agentwatch.detectors.health._window import scaled_turn_window

if TYPE_CHECKING:
    from agentwatch.parser.models import ActionBuffer

_WORD_RE = re.compile(r"[a-z]{2,}")
_SENTENCE_RE = re.compile(r"[^.!?\n]+[.!?]?")


def _content_words(text: str) -> list[str]:
    """Extract lowercase content words (len >= 2)."""
    return _WORD_RE.findall(text.lower())


def _ngrams(words: list[str], n: int = 3) -> list[tuple[str, ...]]:
    if len(words) < n:
        return []
    return [tuple(words[i : i + n]) for i in range(len(words) - n + 1)]


# ---------------------------------------------------------------------------
# Sub-metrics
# ---------------------------------------------------------------------------

def _within_output_repetition(text: str, n: int = 3) -> float:
    """Fraction of 3-grams in *text* that appear more than once."""
    words = _content_words(text)
    grams = _ngrams(words, n)
    if not grams:
        return 0.0

    seen: dict[tuple[str, ...], int] = {}
    for g in grams:
        seen[g] = seen.get(g, 0) + 1

    repeated = sum(c - 1 for c in seen.values() if c > 1)
    return min(repeated / len(grams), 1.0)


def _cross_turn_jaccard(outputs: list[str], k: int = 3) -> float:
    """Average pairwise Jaccard similarity of content-word sets across the
    last *k* outputs compared to the current one."""
    if len(outputs) < 2:
        return 0.0

    current_set = set(_content_words(outputs[-1]))
    if not current_set:
        return 0.0

    previous = outputs[-(k + 1) : -1]
    if not previous:
        return 0.0

    scores: list[float] = []
    for prev in previous:
        prev_set = set(_content_words(prev))
        if not prev_set:
            continue
        intersection = len(current_set & prev_set)
        union = len(current_set | prev_set)
        scores.append(intersection / union if union else 0.0)

    if not scores:
        return 0.0
    return sum(scores) / len(scores)


def _repeated_sentences(outputs: list[str]) -> float:
    """Fraction of sentences in the latest output that appeared verbatim in
    any of the preceding outputs."""
    if len(outputs) < 2:
        return 0.0

    current_text = outputs[-1]
    current_sentences = [s.strip().lower() for s in _SENTENCE_RE.findall(current_text) if len(s.strip()) > 20]
    if not current_sentences:
        return 0.0

    # Build set of prior sentences
    prior_sentences: set[str] = set()
    for prev in outputs[:-1]:
        for s in _SENTENCE_RE.findall(prev):
            stripped = s.strip().lower()
            if len(stripped) > 20:
                prior_sentences.add(stripped)

    if not prior_sentences:
        return 0.0

    repeated = sum(1 for s in current_sentences if s in prior_sentences)
    return repeated / len(current_sentences)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_repetition(buffer: ActionBuffer, k: int | None = None) -> MetricResult:
    """Compute the repetition metric over recent turns."""

    turns = turns_from_buffer(buffer)
    outputs = [t.model_output for t in turns if t.model_output]
    if not outputs:
        return MetricResult(name="repetition", value=0.0)

    if k is None:
        # Scale cross-turn comparison window with session length
        k = max(3, min(10, len(outputs) // 5))

    # Sub-metric: within-output 3-gram repetition (latest output)
    within_rep = _within_output_repetition(outputs[-1])
    within_result = MetricResult(
        name="ngram_self_repeat",
        value=round(within_rep, 4),
        evidence=[f"3-gram self-repeat ratio: {within_rep:.2f}"] if within_rep > 0.1 else [],
    )

    # Sub-metric: cross-turn Jaccard overlap
    jaccard = _cross_turn_jaccard(outputs, k=k)
    jaccard_result = MetricResult(
        name="cross_turn_overlap",
        value=round(jaccard, 4),
        evidence=[f"Jaccard overlap with prior {k} outputs: {jaccard:.2f}"] if jaccard > 0.2 else [],
    )

    # Sub-metric: repeated sentences
    rep_sent = _repeated_sentences(outputs[-min(k + 1, len(outputs)) :])
    sent_result = MetricResult(
        name="repeated_sentences",
        value=round(rep_sent, 4),
        evidence=[f"repeated sentence ratio: {rep_sent:.2f}"] if rep_sent > 0.1 else [],
    )

    # Combine: weighted average (3-gram is noisier, give it less weight)
    combined = 0.25 * within_rep + 0.40 * jaccard + 0.35 * rep_sent

    evidence: list[str] = []
    if within_rep > 0.15:
        evidence.append(f"self-repeating n-grams ({within_rep:.0%})")
    if jaccard > 0.3:
        evidence.append(f"high overlap with prior outputs (Jaccard {jaccard:.0%})")
    if rep_sent > 0.2:
        evidence.append(f"sentences repeated from prior turns ({rep_sent:.0%})")

    return MetricResult(
        name="repetition",
        value=round(min(combined, 1.0), 4),
        evidence=evidence,
        contributors=[within_result, jaccard_result, sent_result],
    )
