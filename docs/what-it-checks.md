---
title: What it checks
description: The problems AgentWatch looks for, in plain words, and what to do when you see one.
hide:
  - navigation
---

# What it checks

AgentWatch reads what your assistant did, one step at a time: each file it read or
changed, each command it ran, and how each one turned out. It runs two kinds of
checks on those steps.

- **Health:** is the assistant getting anywhere, and at what cost? These checks
  are always on.
- **Security:** is it doing something risky? Turn these on with `--security`, or
  press <kbd>s</kbd> in the dashboard.

Every check is a plain rule, such as "the same command failed five times in a
row". No AI is involved, so the same session always gets the same result.

## Health: is it getting anywhere?

### Going in circles

**What it looks like.** The assistant runs the same command and gets the same
error, again and again. Or it changes a file, runs the tests, sees them fail, and
changes the same file again. Or it reads the same file many times over.

**What to do.** Stop it and read the error it keeps hitting. Tell it to try a
different approach, or fix the cause yourself. If you use Claude Code, the
optional [loop breaker](faq.md#can-it-stop-my-assistant) can interrupt a repeat
for you.

### Failing over and over

**What it looks like.** Several steps in a row fail. The same error message comes
back unchanged, as if the assistant didn't read it. Or the same kind of error,
such as a typo in the code, survives one fix after another.

**What to do.** Undo the recent changes, or start again with a different plan. The
error message is usually the best place to start.

### Stuck, no progress

**What it looks like.** The assistant is busy but nothing changes. It reads and
searches without ever editing a file, or keeps circling the same few files.

**What to do.** Give it a more specific instruction: which file to look at, or
what the next step is.

### Losing track as its memory fills

An assistant can only hold so much of the conversation at once. This is its
*context window*.

**What it looks like.** The window is 70% full or more, and 85% is serious. The
assistant goes back to files it read long ago, or stops referring to files it
changed early on.

**What to do.** Start a fresh session with a short summary of where things stand.
Many assistants also have a command that shortens the conversation for you.

AgentWatch can only show how full the window is when the assistant's log says
how big the window is.

### Cost and efficiency

AI services charge by the *token*, a few characters of text. AgentWatch adds up
the tokens in the log and estimates the cost from the AI provider's published
prices. The cost is an estimate, and it shows `n/a` when an assistant doesn't
log tokens or uses a model without a known price.

A separate **efficiency** score (0 to 100) looks at how hard the session is
working its resources: how full its memory is, how fast it spends tokens, how
much it reuses earlier work, and how long it has run. Cost is shown, but doesn't
change any score.

**What to do.** A long, expensive session is a good moment to wrap up and start
fresh. `agentwatch report` shows what your assistants cost over the last week,
and how much went on steps behind a health warning.

## Security: is it doing something risky?

### Passwords, keys and secrets

**What it looks like.** The assistant opens a file that usually holds secrets,
such as `.env`, an SSH key or a cloud login file. A password or API key shows up
in a command or in what it wrote. Or it reads a secret file and then connects to
the internet.

**What to do.** If a key was shown or sent anywhere, replace it: create a new one
and cancel the old one. Hiding it afterwards doesn't make it safe. To share a log
without its secrets, run `agentwatch scrub <file>` first.

### Prompt injection

Prompt injection means instructions hidden in a file, a web page or a tool's
output that try to take over the assistant.

**What it looks like.** Phrases such as "ignore previous instructions", invisible
characters, or encoded commands in what the assistant read.

**What to do.** Find what it was reading, such as a web page, a downloaded file
or a README, and treat that source as untrusted. Check what the assistant did
right after reading it. This check can also fire when the assistant reads text
that is *about* prompt injection, such as security notes.

### Data leaving your computer

**What it looks like.** The assistant reads files and then sends data out, for
example to a paste site. It runs a command that contacts a server on a timer or
in an endless loop. It runs name-lookup commands such as `dig`, which can smuggle
data out. In the live dashboard with security on, AgentWatch also notices
connections that no step announced, such as an install command quietly
contacting an unknown server.

**What to do.** Look at where it connected and why. If you don't recognise the
server, stop the assistant and replace any secrets it had read.

### Dangerous commands

**What it looks like.** It gives itself administrator rights with `sudo`,
deletes files in bulk (for example `rm -rf`), or changes system folders.

**What to do.** Stop the assistant and check what changed. Consider limiting
which commands it may run without asking you first.

### Add-ons (skills)

Some assistants can install *skills*, add-ons that give them new abilities.

**What it looks like.** A new skill is installed or starts running, a skill
connects to the internet, or skills call each other in unusual chains. These
checks were written mainly for Moltbot skills.

**What to do.** Keep only skills you trust, from sources you know.

## Technical details

??? info "All 36 checks, and how the scores are calculated"

    `agentwatch list-detectors --security` lists every check. There are 36: 15
    health checks and 21 security checks.

    **Health checks**

    - Progress: `loop` (same action repeated), `reread` (same file read many
      times), `thrash` (edit, test, fail, repeat), `stall` (no meaningful
      progress), `same_outcome` (different fixes, same error), `file_churn` (a
      file edited again and again without a passing test), `exploration_stall`
      (no new files explored).
    - Errors: `error_spiral` (failures in a row), `error_blindness` (the same
      error ignored), `error_class_persistence` (the same kind of error after
      different fixes), `syntax_loop` (repeated syntax or import errors),
      `high_error_rate`.
    - Context: `context_pressure` (the context window filling up),
      `context_rot` (early files no longer referred to), `rediscovery` (files
      read again after a long gap).

    **Security checks**

    - Credentials: `credential_access`, `secret_in_output`, `credential_exfil`
      (secret access followed by network activity), `secret_leak_scanner`.
    - Injection: `prompt_injection`, `hidden_instruction`, `indirect_injection`.
    - Exfiltration: `data_exfiltration`, `dns_exfiltration`.
    - Network: `network_anomaly`, `c2_communication` (contacting a server on a
      timer or in a loop), `undeclared_egress` (live only: a connection no
      step announced).
    - Privilege: `privilege_escalation`, `dangerous_command`,
      `mass_file_operation`, `sensitive_directory`.
    - Supply chain: `malicious_skill`, `skill_network`, `new_skill`,
      `skill_chain`, `skill_install`.

    **How the health score works**

    1. Each warning has a severity, which takes points off its category's 100:
       low 5, medium 15, high 30, critical 50.
    2. The categories are averaged with weights: progress 35%, errors 30%,
       context 20% and goal 15%. No check uses the goal category yet, so it
       always scores 100.
    3. With security on, the six security categories join the average:
       injection 25%, credential 20%, exfiltration 20%, privilege 15%, network
       10% and supply chain 10%.
    4. `agentwatch check` reports that average. The live dashboard blends it
       (40%) with the efficiency score (30%) and a context health score (30%).

    The **efficiency score** starts at 100 and loses points for: how full the
    context window is (30%), token spend per minute (20%, from 5,000 up to
    30,000 fresh tokens a minute), input compared with output (10%), cache
    misses (15%), steps per reply (10%) and session length (15%, from 30 up to
    90 minutes). Spend rates are ignored for the first two minutes.

    The **context health score** combines five measures: behaviour 20%,
    repetition 20%, tool thrashing 25%, progress 25% and project rules 10%. It is
    smoothed over time, so it only drops after a sustained decline. In the
    first turns of a session its stall measure counts for less, so a greeting
    or a quick question doesn't lower it.

    The **security score** is 100 with no findings and 0 after any critical
    finding. Otherwise each finding takes off its points. Secure is 100, at risk
    is 50 to 99, compromised is below 50.

    The ranges for the words are 80 and up, 60 to 79, 40 to 59, and below 40.
    `agentwatch themes` lists the sets of words you can choose from.

    With the optional `--llm` flag, a local AI model (Ollama, on your own
    computer) adds a second opinion on the warnings. It never changes a score.
