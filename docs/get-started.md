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
    installer, tick **Add python.exe to PATH**. Then open a new terminal window.

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

    Close the Terminal window, open a new one, and install AgentWatch:

    ```bash
    pipx install agentwatch-monitor
    ```

=== "Windows"

    ```powershell
    py -m pip install --user pipx
    py -m pipx ensurepath
    ```

    Close the terminal window, open a new one, and install AgentWatch:

    ```powershell
    pipx install agentwatch-monitor
    ```

=== "Linux"

    On Debian or Ubuntu use `apt`, on Fedora `dnf`:

    ```bash
    sudo apt install pipx
    pipx ensurepath
    ```

    Close the terminal, open a new one, and install AgentWatch:

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

This is a real report, from a sample session in AgentWatch's own tests where
most steps failed:

```text
══════════════════════════════════════════════════
  HEALTH REPORT
══════════════════════════════════════════════════

  Overall:   🚀 PRODUCTIVE (86%)

  Errors       🔄 55%

  Efficiency: 100% (productive), 0% ctx, 0% cache hit

  🔄 2 warning(s):

     🔴 [error_spiral] Error spiral: 5 consecutive failures
        💡 Nothing has succeeded recently. Consider reverting recent changes or trying a completely different approach.

     ⚠️ [high_error_rate] High error rate: 60% of actions failing (6/10)
        💡 6 out of 10 recent actions failed. The agent may be in an unrecoverable state for this approach.
```

How to read it:

- **Overall** is the health score, from 0 to 100, and its word. The score
  combines several areas, so one bad area lowers it without sinking it. The
  warnings are the part to read.
- **Errors 55%** is an area that lost points. Areas with no problems aren't
  listed.
- **Efficiency** is about resources: how full the assistant's memory is, and
  how much it reuses earlier work (the cache).
- **Each warning** gives the problem's name in brackets, what happened, and a
  suggestion on the line below.

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

The security verdict is separate: **secure** (100, nothing found), **at risk**
(50–99) or **compromised** (below 50). A single critical finding means
compromised.

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
