# AgentWatch Scrub Skill: Design

Date: 2026-10-15
Branch: `feature/agentwatch-skill` (from `develop` @ 57f9204)
Status: approved by the board with the CTO review changes folded in (2026-10-15)

## In plain terms

A developer tells Claude Code "scrub my logs" or "clean this file before I
share it". Claude runs AgentWatch, which hides passwords, API keys and personal
info (emails, phone numbers, street addresses, SSNs, card numbers) and reports
what it hid. The original file is never changed unless the developer asks.

## Who it is for

Developers using AI coding agents, in Claude Code. A consumer version for
non-developers and a Claude Desktop version are parked (see Out of scope).

## What exists today

- `agentwatch audit --redact` finds and hides secrets (API keys, tokens,
  passwords, connection strings) in Claude Code session logs
  (`~/.claude/projects/*.jsonl`) only. Backups kept as `<log>.bak`.
- Detection and redaction live in `detectors/security/secret_scanner.py`
  (`_SECRET_PATTERNS`, `_redact_text`, `_redact_line`, `redact_log_file`).
- Nothing detects personal info. Nothing cleans an arbitrary file.
- The `private_key` pattern (`secret_scanner.py:94`) matches only the
  `-----BEGIN ... PRIVATE KEY-----` header, so redaction leaves the key body.

## What we build

### 1. Personal-info patterns: `detectors/security/pii.py` (new)

`_PII_PATTERNS: list[tuple[re.Pattern, str]]`, same shape as
`_SECRET_PATTERNS`, compiled **without** `re.IGNORECASE` (`_p()` in
`secret_scanner.py` forces it; the address rule needs case).

| Label | Matches | Rejects |
|---|---|---|
| `email` | `user@domain.tld` | `example.com/.org/.net` (already skipped by `_PLACEHOLDER_RE`), `noreply@`, `users.noreply.github.com`, `git@` (SSH remotes), local part ending `@<digit>x` (`icon@2x.png`), a "TLD" that is a common file extension (`png jpg jpeg gif svg webp js ts py json md txt css html`) |
| `phone` | E.164 `+` and 10-15 digits; US `(555) 123-4567`, `555-123-4567`, `555.123.4567` | bare digit runs; a match touching another digit or word char |
| `us_ssn` | `123-45-6789` (dashes required) | area `000`/`666`/`9xx`, group `00`, serial `0000` |
| `credit_card` | 13-19 digits, optional single spaces/dashes between groups | no issuer prefix (`4`, `5[1-5]`, `2[2-7]`, `3[47]`, `6011`, `65`); fails Luhn; touching another digit, hex or word char (so 13-digit ms timestamps, snowflake ids, hashes) |
| `street_address` | house number (1-5 digits) + 1-4 Title Case words + Title Case suffix (`St Ave Rd Blvd Dr Ln Ct Way Pl Ter Pkwy Hwy`, full forms too), optional `Apt/Suite/Unit N` | lower-case words or suffix ("fixed 3 bugs this way"). Best effort |

Checks a regex cannot express (Luhn, issuer prefix, email skip list) go in
`_PII_VALIDATORS: dict[label, Callable[[str], bool]]` (True = real). The one
hook is `_is_placeholder()` (`secret_scanner.py:788`): it returns True when the
label has a validator that rejects the value. `_redact_text` and
`_first_live_match` both already call it, so detection and redaction agree.

Known gap, accepted: `_PLACEHOLDER_RE` skips any value containing `todo`,
`example`, `dummy`, `placeholder` (case-insensitive), so `todorov@gmail.com`
is missed.

PII is **not** added to the live `SecretLeakScanner`. Emails appear in every
git commit and would flood `watch` with warnings. PII is only used when the
user asks (`scrub`, `audit --pii`).

### 2. Reuse in `secret_scanner.py`

- `patterns` argument (default `_SECRET_PATTERNS`) threaded through **every**
  layer, not only `_redact_text`: `_redact_text`, `_redact_json_value`,
  `_redact_line`, `redact_log_file`, `_first_live_match`, `audit_log_file`.
  `_redact_line`'s fallback and decoded-escape passes call
  `_redact_json_value`; if `patterns` stopped at `_redact_text` those passes
  would silently use the secret-only default.
- `_find_spans(text, patterns) -> list[tuple[int, int, str]]`: the merged
  value spans `_redact_text` already computes, with the label of the first
  span in each merge. `_redact_text` is rebuilt on it; `scrub --dry-run`
  reports from it. Dry-run and a real run therefore always agree.
- New `private_key_block` pattern: `-----BEGIN <kind>PRIVATE KEY-----`, body,
  matching `-----END ...-----`, across real newlines and JSON `\n` escapes.
  The body is redacted (the header may be too). The header-only patterns stay
  for detection of truncated keys.

### 3. New command: `agentwatch scrub <path>`

Cleans one file: JSONL agent logs, `.env`, plain text, source files.

- Default: secrets **and** PII. `--secrets-only` turns PII off.
- Default writes a cleaned copy beside the original, named
  `path.with_name(path.stem + ".scrubbed" + path.suffix)`: `notes.txt` ->
  `notes.scrubbed.txt`, `.env` -> `.env.scrubbed`, `run.jsonl` ->
  `run.scrubbed.jsonl`. An existing copy is overwritten (it is derived
  output). The copy keeps the original's permission mode. The original is
  untouched.
- `--in-place` overwrites the original atomically (`_atomic_write_bytes`),
  keeping `<file>.bak` (mode 0600). If `<file>.bak` already exists, scrub
  refuses with exit 2: `redact_log_file` never refreshes a `.bak`, so a second
  in-place run would destroy values added since the first.
- `--dry-run` writes nothing and lists findings (type, 1-based line, masked
  preview via `_mask_value`). Wins over `--in-place`.
- `--json` prints one object:
  `{"file", "output", "backup", "dry_run", "redacted", "findings": [{"type", "line", "preview"}]}`
  (`output`/`backup` are `null` when not written). Never an unmasked value.
- `.jsonl` files go line by line through `_redact_line` (valid JSON lines stay
  valid with the same keys). Every other file is one `_redact_text` call on
  the whole text, so multi-line blocks (PEM keys) match.
- Bytes decoded with `surrogateescape` (same as `redact_log_file`), so
  invalid UTF-8 round-trips. A NUL byte in the first 8 KiB means binary:
  refuse, exit 2.
- Exit codes:
  - real run: `0` success (whether or not anything was hidden), `2` error.
  - `--dry-run`: `0` nothing found, `1` something found (CI gate), `2` error.
  - Errors: missing path, directory, binary file, existing `.bak` with
    `--in-place`, I/O failure. Click usage errors are also 2.
  - These differ from `check`/`audit`, where 2 means critical findings;
    README's Exit Codes section documents `scrub` separately.

### 4. `agentwatch audit --pii`

One new flag. With it, `audit_log_file` and `redact_log_file` use
`_SECRET_PATTERNS + _PII_PATTERNS`. PII findings get severity `low` (never
the channel severity) and their own remediation text ("personal info; remove
it before sharing this log"). Because `audit`'s exit code looks only at
`critical`/`high` (`cli.py:1690-1695`), PII never changes it.
`assess_impact` already tolerates unknown labels (`_pattern_for_secret_type`
returns `None`). Without `--pii`, `audit` behaves exactly as today. `audit`
keeps its active-session skip (`cli.py:1591`), which is why the skill sends
agent logs here instead of `scrub --in-place`.

### 5. The skill: `skills/agentwatch-scrub/SKILL.md` (new, Claude Code only)

One `SKILL.md` (frontmatter `name`, `description`) that tells Claude:

- **When to use it:** the user says scrub, sanitize, redact, clean before
  sharing, "did I leak a key", or is about to paste a log or file into an
  issue, PR or chat.
- **Check first:** run `agentwatch scrub --help`. Installed versions that
  predate `scrub` lack it.
- **If missing:** ask before installing. Offer the no-install route
  `uvx --from agentwatch-monitor agentwatch scrub ...` or
  `pip install -U agentwatch-monitor`. Never install without a yes.
- **What to run:** `agentwatch scrub <file> --dry-run --json` first, show the
  masked findings, then run it for real (copy by default; `--in-place` only
  if the user asks). For one Claude Code session log:
  `agentwatch scrub <log>.jsonl` (dry-run first), which writes
  `<log>.scrubbed.jsonl` and catches personal info typed into prompts and
  secrets in tool results; the skill then moves that copy out of
  `~/.claude/projects/` (where `stats`, `audit`, discovery and `/resume`
  glob `*.jsonl` and would count it as a session), never copying the
  original out first. For in-place redaction across many logs:
  `agentwatch audit --redact --pii` (it skips the live session's log); the
  skill says plainly that `audit` does not look at user prompts or tool
  results, so the scrubbed copy is the safe file to share. Never
  `scrub --in-place` an active session log (including this session's own).
- **Exit codes:** real run 0 = done; dry-run 1 = found something (not a
  failure); 2 = error, show the message.
- **Safety rules:** never Read, cat or print the original file (its secrets
  would land in this session's own log); never print an unmasked value; say a
  `.bak` still holds the originals; tell the user to rotate any leaked key,
  because hiding it in a log does not make it safe.

**Board decision (2026-10-15):** option 2 chosen. The skill uses `scrub`
for single session logs; `audit`'s channels are unchanged (prompts and tool
results stay outside its scope).

Install: copy the folder to `~/.claude/skills/agentwatch-scrub/`. README gets
a short "Scrub skill" section with that step.

## Out of scope

- The consumer / average-person version (parked).
- Claude Desktop (parked). Its sandbox cannot see host files such as
  `~/.claude` logs, so the user would have to upload the file first, which
  shares the very data the skill protects; pip access is also unconfirmed.
- Automatic redaction during `watch` / `watch-all`.
- Names, dates of birth, non-US addresses and IDs (need NLP, not regex).
- Scanning whole directories with `scrub` (one file per call; Claude loops).
- Non-Claude-Code logs in `audit` (unchanged scope).
- A CLI guard against `scrub --in-place` on a live agent log (the skill
  rule and the copy-by-default cover v1).

## Acceptance criteria

1. Each PII label has tests for at least 2 real matches and 2 look-alikes it
   must ignore, including: a Luhn-invalid 16-digit number, a Luhn-valid
   13-digit ms timestamp (`1760486400000`-style, no issuer prefix),
   `user@example.com`, `git@github.com:org/repo.git`, `icon@2x.png`,
   "fixed 3 bugs this way", SSN area `000`/`666`/`9xx`.
2. A fixture seeded with N known values (secrets and each PII type, including
   a full multi-line PEM private key): `agentwatch scrub file.txt` writes
   `file.scrubbed.txt` in which none of the N raw values (and no base64 line
   of the key body) appears, reports `redacted == N`, and leaves `file.txt`
   byte-identical.
3. `agentwatch scrub log.jsonl`: every line that was valid JSON is still
   valid JSON with the same keys; non-JSON lines are redacted as text.
4. `--dry-run` writes no files and reports the same count a real run then
   redacts. `--json` and human output contain none of the seeded raw values.
5. `--in-place` creates `.bak` (mode 0600 on Unix) and replaces the file
   atomically; with an existing `.bak` it exits 2 and changes nothing.
6. Running `scrub` on its own output redacts 0 (idempotent).
7. Exit codes: real run 0; dry-run 0 clean / 1 found; missing path, binary
   file (NUL byte) and existing `.bak` with `--in-place` exit 2.
8. Output naming: `.env` -> `.env.scrubbed`, `notes.txt` ->
   `notes.scrubbed.txt`; an existing copy is overwritten.
9. `agentwatch audit` without `--pii` gives identical output to `develop`
   (existing tests unchanged and passing). With `--pii`, PII findings are
   severity `low` and do not change the exit code.
10. `SecretLeakScanner.check()` returns no warning for a buffer whose only
    sensitive content is an email, phone, SSN, card number and address.
11. `--secrets-only` leaves PII untouched.
12. `SKILL.md` is under 150 lines, has valid frontmatter (`name`,
    `description`), and is live-tested once in Claude Code by asking "scrub
    this file" on a fixture with a fake key and a fake address.
13. README documents `scrub`, its exit codes, and the skill install step.
14. `ruff check .` and `python -m pytest tests/` pass.
