---
name: agentwatch-scrub
description: Hide secrets (API keys, tokens, passwords, private keys) and personal info (emails, phones, SSNs, card numbers, addresses) in a file or Claude Code session log using agentwatch. Use when the user says scrub, sanitize, redact, clean before sharing, "did I leak a key", or is about to paste a log or file into an issue, PR or chat.
---

# agentwatch-scrub

Clean a file or a Claude Code session log before it is shared, using the
`agentwatch` CLI. agentwatch finds the values and replaces them; you never
look at them yourself.

## Safety rules (always)

- Never Read, cat, head, grep or otherwise print the original file. Its
  secrets would land in this session's own log.
- Never print an unmasked value. Only show the masked previews agentwatch
  gives you.
- After an `--in-place` run or `audit --redact`, tell the user the `.bak`
  file still holds the original values, and to delete it once they have
  checked the result.
- If a secret (key, token, password) was found, tell the user to rotate it.
  Hiding it in a file does not make it safe; it may already be in git
  history, a chat, or a backup.

## 1. Check agentwatch is there

Run:

```bash
agentwatch scrub --help
```

If that fails (command not found, or no such command `scrub`, which means
an older version), ask the user before installing anything. Offer:

- No install: `uvx --from agentwatch-monitor agentwatch scrub ...`
  (use this prefix in place of `agentwatch` below)
- Install or upgrade: `pip install -U agentwatch-monitor`

Do not install without a yes.

## 2. A normal file (.env, .txt, .jsonl, source, a copied log)

Always dry run first:

```bash
agentwatch scrub <file> --dry-run --json
```

Show the user what was found: each finding's `type`, `line` and masked
`preview`, and the `redacted` count. If nothing was found, say so and stop.

Then run it for real:

```bash
agentwatch scrub <file>
```

This writes a cleaned copy beside the original (`notes.txt` ->
`notes.scrubbed.txt`, `.env` -> `.env.scrubbed`) and leaves the original
untouched. Tell the user the path of the copy; that is the file to share.

Only if the user asks to change the file itself:

```bash
agentwatch scrub <file> --in-place
```

This keeps the original as `<file>.bak`. If a `.bak` already exists, scrub
refuses (exit 2); tell the user and let them decide what to do with the old
`.bak`. Do not delete it yourself.

Add `--secrets-only` if the user wants personal info left alone.

## 3. Claude Code session logs (~/.claude/projects/)

To share or clean one session log, use `scrub`. Dry run first, same as
for any file:

```bash
agentwatch scrub <log>.jsonl --dry-run --json
agentwatch scrub <log>.jsonl             # writes <log>.scrubbed.jsonl
```

This catches personal info the user typed into prompts and secrets in tool
results. The scrubbed copy is the safe file to share.

To hide findings in place across many logs, use `audit`. It skips the log
of a session that is still running.

```bash
agentwatch audit --pii                   # current project, report only
agentwatch audit --redact --pii          # hide the findings
agentwatch audit --all --redact --pii    # every project
```

`audit` does NOT look at user prompts or tool results. Personal info typed
into a prompt stays in the log after `audit`; tell the user so, and share
the `scrub` copy instead.

Never run `scrub --in-place` on an active session log, one an agent is
still writing (including this session's own log).

## 4. Exit codes

`scrub`:

| Run      | 0                | 1                | 2     |
| -------- | ---------------- | ---------------- | ----- |
| real     | done             | -                | error |
| dry run  | nothing found    | found something  | error |

Dry-run exit 1 is not a failure; it means there is something to hide.
On exit 2 (missing file, directory, binary file, existing `.bak` with
`--in-place`), show the user the error message.

`audit` exits 2 for critical and 1 for high secret findings; personal
info never changes its exit code.

## 5. Report back

Keep it short:

- what was found (counts by type, masked previews only)
- where the clean copy is, or which files were changed
- the `.bak` reminder, if one was written
- "rotate these keys" for every leaked secret
