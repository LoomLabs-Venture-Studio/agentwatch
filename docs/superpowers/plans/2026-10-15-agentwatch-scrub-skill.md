# AgentWatch Scrub Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for every task (failing test first, then code). Steps use checkbox (`- [ ]`) syntax.

**Goal:** `agentwatch scrub <file>` and `agentwatch audit --pii` hide secrets and personal info, and a Claude Code skill drives them.

**Architecture:** Detection/redaction stays in `detectors/security/secret_scanner.py`. A new stdlib-only `detectors/security/pii.py` holds `_PII_PATTERNS` and `_PII_VALIDATORS`; `secret_scanner.py` imports from it (never the reverse, no cycle). Every redaction function takes a `patterns` argument defaulting to `_SECRET_PATTERNS`, so today's callers are unchanged. `scrub` is a thin Click command over one core function.

**Spec:** `docs/superpowers/specs/2026-10-15-agentwatch-scrub-skill-design.md` (the acceptance criteria there are the contract; AC numbers below refer to it).

## Global Constraints

- Python `>=3.11`; ruff line-length 100, rules E/F/I/N/W. No new dependencies, no new env vars.
- Branch `feature/agentwatch-skill` only. Never touch `main`. Do not push (the CTO pushes).
- One commit per task, format `type(scope): description`, message ending with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Dev env: `pip install -e ".[dev,siem,llm]"`. Gate: `ruff check .` and `python -m pytest tests/ -q` green after every task.
- Existing tests must not be edited to make them pass (AC9). Add new tests in new files.
- Never print or log an unmasked matched value anywhere.

## Review Focus

- `patterns` reaches `_redact_json_value` in `_redact_line`'s fallback and decoded-escape passes (a PII value behind a JSON `\n` escape must still be redacted).
- `_is_placeholder` is the only place validators run; `_redact_text` and `_first_live_match` must not grow their own checks.
- PII patterns compiled without `re.IGNORECASE`.
- PEM block regex body bounded (e.g. `{1,20000}?`) so an unterminated `BEGIN` cannot go quadratic over a large file.
- `scrub` dry-run count equals the real-run count because both come from the same function.

---

### Task 1: Thread `patterns` and add `_find_spans` (refactor, no behaviour change)

**Files:** Modify `src/agentwatch/detectors/security/secret_scanner.py`. Create `tests/test_scrub_core.py`.

- Add `_find_spans(text, patterns=_SECRET_PATTERNS) -> list[tuple[int, int, str]]`: today's span collection + merge from `_redact_text` (`secret_scanner.py:814-845`), returning merged spans with the label of the first span in each merge.
- Rebuild `_redact_text(text, patterns=_SECRET_PATTERNS)` on `_find_spans`.
- Add `patterns` (keyword, default `_SECRET_PATTERNS`) to `_redact_json_value`, `_redact_line`, `redact_log_file`, `audit_log_file`. `_first_live_match` already takes one pattern; `audit_log_file` loops over `patterns` instead of `_SECRET_PATTERNS`.
- Test: a custom one-entry pattern list passed to `_redact_line` redacts a value that only shows after JSON-escape decoding (proves the decoded pass got `patterns`), and is ignored by the default.
- Commit: `refactor(redact): thread a patterns argument through redaction`

### Task 2: Redact whole PEM private key blocks

**Files:** Modify `secret_scanner.py`. Add tests to `tests/test_scrub_core.py`.

- New `_p(...)` entry `private_key_block`: `-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----` + bounded lazy body as the `secret` group (matches real newlines and literal `\n` escapes) + `-----END ...-----`. Keep the header-only patterns.
- Tests: a multi-line PEM in plain text via `_redact_text` leaves no body line; the same key inside a JSONL string (with `\n` escapes) via `_redact_line` leaves no body and stays valid JSON; a header with no END still redacts the header and finishes fast on a 1 MB string.
- Commit: `fix(redact): redact private key bodies, not only the header`

### Task 3: PII patterns and validators

**Files:** Create `src/agentwatch/detectors/security/pii.py`, `tests/test_pii.py`. Modify `secret_scanner.py` (`_is_placeholder` hook only).

- `pii.py` (stdlib only): `_PII_PATTERNS`, `_PII_VALIDATORS`, `PII_LABELS = frozenset(...)`, `_luhn(digits) -> bool`. Labels and rules exactly as the spec table (email, phone, us_ssn, credit_card, street_address). Use `(?<![\w.-])`/`(?![\w-])`-style boundaries so digits inside longer runs/hex never match.
- `_is_placeholder(m, label, file_path)`: if `label in _PII_VALIDATORS` and the validator rejects `_match_value(m)`, return True; otherwise current behaviour.
- Tests (AC1): per label at least 2 real matches and 2 look-alikes, including every look-alike the spec AC1 lists. Test through `_redact_text(text, _SECRET_PATTERNS + _PII_PATTERNS)` so the hook is exercised. Add AC10: `SecretLeakScanner().check(buffer)` returns `None` for an action containing only an email, phone, SSN, card and address. Add AC11-style test: default `_redact_text(text)` leaves PII untouched.
- Commit: `feat(pii): add personal-info patterns for redaction`

### Task 4: `agentwatch scrub`

**Files:** Modify `secret_scanner.py` (core function), `src/agentwatch/cli.py` (command). Create `tests/test_scrub_cli.py`.

- Core: `scrub_file(path, *, patterns, in_place=False, dry_run=False) -> ScrubResult` (dataclass: `file`, `output`, `backup`, `dry_run`, `redacted`, `findings: list[dict(type, line, preview)]`). Behaviour per spec section 3: NUL in first 8 KiB -> raise; `.jsonl` -> line-wise `_redact_line`; else one `_redact_text` on the whole text; findings from `_find_spans` (for `.jsonl` lines, from the same per-line work); `preview` via `_mask_value`; output name `path.with_name(path.stem + ".scrubbed" + path.suffix)` written with `_atomic_write_bytes` at the original mode; `--in-place` refuses if `.bak` exists, else writes `.bak` (0600) then replaces atomically. Reuse `_atomic_write_bytes`; do not copy it.
- CLI: `scrub PATH [--secrets-only] [--in-place] [--dry-run] [--json]`. Exit codes per spec (real 0, dry-run 0/1, errors 2). Human output: count, output/backup path, `.bak` warning, masked findings.
- Tests (CliRunner, `tmp_path`): AC2 (seeded N values incl. PEM, `redacted == N`, original byte-identical), AC3, AC4 (no raw value in stdout for `--json` and human), AC5 (0600 skipped on Windows like existing tests), AC6, AC7, AC8, AC11.
- Commit: `feat(cli): add agentwatch scrub for one file`

### Task 5: `agentwatch audit --pii`

**Files:** Modify `cli.py` (`audit`), `secret_scanner.py` (`audit_log_file` severity/remediation for PII labels). Create `tests/test_audit_pii.py`.

- `--pii` passes `_SECRET_PATTERNS + _PII_PATTERNS` to `audit_log_file` and `redact_log_file`. In `audit_log_file`, a label in `PII_LABELS` gets severity `"low"` and remediation "Personal info; remove it before sharing this log".
- Tests (AC9): a session log with only an email: `audit --all --json` finds nothing (unchanged); `audit --all --pii --json` finds it with severity `low`, exit 0; `--pii --redact` removes it and keeps `.bak`.
- Commit: `feat(audit): add --pii to find and redact personal info in session logs`

### Task 6: Skill and README

**Files:** Create `skills/agentwatch-scrub/SKILL.md`. Modify `README.md`.

- `SKILL.md` per spec section 5, under 150 lines, frontmatter `name: agentwatch-scrub` and a `description` that names the trigger phrases. Include the exit-code meanings and every safety rule verbatim in intent.
- README: `scrub` under Usage, a `scrub` row/note in Exit Codes (its own table: real 0/2, dry-run 0/1/2), `audit --pii`, and a "Scrub skill" install section (`~/.claude/skills/agentwatch-scrub/`). Claude Code only.
- Test: a small pytest that parses the frontmatter (name, description present) and asserts < 150 lines.
- Commit: `docs(skill): add the agentwatch-scrub Claude Code skill and README`

---

## Verification (QA)

- Every spec AC 1-14 checked; AC12's live run: in Claude Code, with the skill copied to `~/.claude/skills/`, ask "scrub this file" on a fixture containing a fake key and a fake address; record that the dry-run ran first, no raw value was printed, and the copy was written.
