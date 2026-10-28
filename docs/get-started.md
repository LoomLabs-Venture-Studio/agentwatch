---
title: Get started
description: Install AgentWatch on Mac, Windows or Linux, run your first check, and open the live dashboard.
hide:
  - navigation
---

# Get started

You will install AgentWatch, check a recent session, and then open the live
dashboard next to your assistant. Everything happens in a terminal, the app where
you type commands. You don't need to know how to program.

## What you need

- A Mac, a Windows PC or a Linux computer.
- **Python 3.11 or newer.** Python is the language AgentWatch is written in. You
  won't write any, but it has to be installed.
- **A terminal.** The steps below show how to open one.

### Open a terminal and check Python

=== "Mac"

    Open **Terminal**: press <kbd>Cmd</kbd> + <kbd>Space</kbd>, type `Terminal` and
    press <kbd>Return</kbd>. Then type this and press <kbd>Return</kbd>:

    ```bash
    python3 --version
    ```

    If it shows `Python 3.11` or a higher number, you're ready. If it shows an
    older version, or says the command isn't found, download the macOS installer
    from [python.org/downloads](https://www.python.org/downloads/), run it, and
    open a new Terminal window.

=== "Windows"

    Open **Terminal** (Windows 11) or **PowerShell** (Windows 10) from the Start
    menu. Then type this and press <kbd>Enter</kbd>:

    ```powershell
    py --version
    ```

    If it shows `Python 3.11` or a higher number, you're ready. If it shows an
    older version, or the command isn't found, download the Windows installer
    from [python.org/downloads](https://www.python.org/downloads/). In the
    installer, tick **Add python.exe to PATH**, which lets your terminal find
    Python. Then open a new terminal window.

=== "Linux"

    Open your terminal app (often <kbd>Ctrl</kbd> + <kbd>Alt</kbd> + <kbd>T</kbd>).
    Then type:

    ```bash
    python3 --version
    ```

    If it shows `Python 3.11` or a higher number, you're ready. If not, install a
    newer Python with your system's package manager.

## Install AgentWatch

The easiest way is **pipx**, a small installer for command-line tools. It keeps
each tool in its own space, so nothing clashes with other software on your
computer. Install pipx first, then AgentWatch.

=== "Mac"

    With [Homebrew](https://brew.sh):

    ```bash
    brew install pipx
    pipx ensurepath
    ```

    `pipx ensurepath` lets your terminal find the commands pipx installs. It
    takes effect in a new window, so close the Terminal window, open a new one,
    and install AgentWatch:

    ```bash
    pipx install agentwatch-monitor
    ```

=== "Windows"

    ```powershell
    py -m pip install --user pipx
    py -m pipx ensurepath
    ```

    `pipx ensurepath` lets your terminal find the commands pipx installs. It
    takes effect in a new window, so close the terminal window, open a new one,
    and install AgentWatch:

    ```powershell
    pipx install agentwatch-monitor
    ```

=== "Linux"

    On Debian or Ubuntu use `apt`, on Fedora `dnf`:

    ```bash
    sudo apt install pipx
    pipx ensurepath
    ```

    `pipx ensurepath` lets your terminal find the commands pipx installs. It
    takes effect in a new window, so close the terminal, open a new one, and
    install AgentWatch:

    ```bash
    pipx install agentwatch-monitor
    ```

Check that it worked:

```bash
agentwatch --version
```

It prints `agentwatch, version 0.2.1`, or a newer number.

??? note "Prefer plain pip?"

    `pip install agentwatch-monitor` works too, ideally inside a Python virtual
    environment. If pip stops with an "externally managed environment" error,
    use pipx as shown above.

## Your first check

Go to the folder of a project where you have used Claude Code, and run:

```bash
agentwatch check
```

It reads your most recent Claude Code session for that folder (or, if there is
none, your most recent one anywhere) and prints a report. To check another
assistant's log file, give its path: `agentwatch check --log <file>`. The live
dashboard below finds every supported assistant by itself.

Here is a real report. The session is made up: the assistant got a build
working, then ran the same failing test six times in a row.

```text
══════════════════════════════════════════════════
  HEALTH REPORT
══════════════════════════════════════════════════

  Overall:   😓 STRUGGLING (71%)

  Progress     😓 70%
  Errors       🔄 40%

  Efficiency: 96% (productive), 9% ctx, 97% cache hit
  Peak context: 91,860 tokens (single action)
  Waste: ~$0.24 on 3 findings (72% of session cost)

  🔄 3 warning(s):

     🔴 [loop] Repeated action: Bash (6x)  ~$0.24 · 462k tok
        → FAIL src/validate.test.ts: expected true, got false
        💡 The exact same action is being repeated. The command "npm test" keeps failing — try a fundamentally different approach.

     🔴 [error_spiral] Error spiral: 5 consecutive failures  ~$0.20 · 400k tok
        💡 Nothing has succeeded recently. Consider reverting recent changes or trying a completely different approach.

     🔴 [error_blindness] Same error repeated 6x without fix  ~$0.24 · 462k tok
        → FAIL src/validate.test.ts: expected true, got false
        💡 The error "FAIL src/validate.test.ts: expected true, got false" keeps appearing unchanged. The agent isn't reading or ad
```

How to read it:

- **Overall** is the health score, from 0 to 100, and its word.
- **Progress 70%** and **Errors 40%** are the scores, out of 100, of the areas
  that lost points. They aren't percentages of steps. Areas with no problems
  aren't listed.
- **Efficiency** is about resources: how full the assistant's memory is, and
  how much it reuses earlier work (the cache). **Waste** is the estimated cost
  of the steps behind the warnings.
- **The warnings** are what to act on. Each gives the problem's name in
  brackets, what happened, the error it got (after the arrow), and a suggestion
  (after the light bulb).

Add `--security` to run the security checks as well:

```bash
agentwatch check --security
```

## Open the live dashboard

Open a second terminal window, next to the one your assistant runs in, and
start the dashboard:

```bash
agentwatch watch-all
```

It finds the assistants running on your computer and shows one row per session:
its health, estimated cost, how full its memory is, how long since its last
step, and its top problem. Sessions that need you are listed first.

| Key | What it does |
| --- | --- |
| <kbd>↑</kbd> <kbd>↓</kbd> | Choose a session |
| <kbd>Enter</kbd> | Open the session's details |
| <kbd>s</kbd> | Turn the security checks on or off |
| <kbd>?</kbd> | Show every key and what the columns mean |
| <kbd>q</kbd> | Quit |

Prefer to be told instead of watching? This runs without the dashboard and shows
a desktop notification when a session's score turns critical or a critical
problem appears:

```bash
agentwatch watch-all --headless --notify
```

??? tip "Boxes or question marks instead of symbols on Windows?"

    The old Windows console can't draw some symbols. Use **Windows Terminal**
    (built into Windows 11), the terminal inside VS Code, or switch AgentWatch to
    plain text:

    ```powershell
    agentwatch --theme ascii watch-all
    ```

## Optional: a coach inside Claude Code

If you use Claude Code, AgentWatch's plugin can step in while Claude works:

- **Coaching.** After each step it checks the session. When a serious loop,
  error spiral or stuck pattern shows up, it adds a short note for Claude: what
  is wrong, and what to try instead. Each problem is noted once.
- **Loop breaker.** When the same step has run 6 or more times in the last 10,
  it blocks the next identical step once and tells Claude why. Commands that
  are meant to repeat, such as running tests, are never blocked.

The plugin needs AgentWatch 0.2.0 or newer, installed as above. Then type these
two commands in Claude Code:

```text
/plugin marketplace add LoomLabs-Venture-Studio/agentwatch
/plugin install agentwatch@agentwatch
```

On Claude Code 2.1.275 or newer, one command does both:
`/plugin install agentwatch --marketplace LoomLabs-Venture-Studio/agentwatch`.

To turn the loop breaker off, set the environment variable
`AGENTWATCH_LOOP_BREAKER` to `off` before you start Claude Code.

## Reading the result

The health score runs from 0 to 100. AgentWatch describes each range in a word:

| Score | Word | What it means |
| --- | --- | --- |
| 80–100 | productive | Working normally. |
| 60–79 | struggling | Something is slowing it down. Keep an eye on it. |
| 40–59 | spinning | It's wasting effort. Time to step in. |
| 0–39 | stuck | It isn't getting anywhere. Stop it and change course. |

With `--theme classic` the same ranges are called healthy, degraded, warning and
critical.

For security, `agentwatch security-scan` gives a one-word verdict: **secure**
(100, nothing found), **at risk** (50–99) or **compromised** (below 50). A
single critical finding means compromised. `check --security` and the dashboard
list the security findings themselves, without that word.

[What it checks](what-it-checks.md) explains each warning and what to do about it.

## Upgrade

```bash
pipx upgrade agentwatch-monitor
```

With plain pip: `pip install --upgrade agentwatch-monitor`.

## Uninstall

If you have used the dashboard or `agentwatch report`, AgentWatch also keeps a
small history file of your sessions on your computer. To remove it too, first run
`agentwatch history path`, which prints where the file is, and delete that file.
Then:

```bash
pipx uninstall agentwatch-monitor
```

With plain pip: `pip uninstall agentwatch-monitor`.
