---
template: home.html
title: Know when your AI coding assistant needs you
hide:
  - navigation
  - toc
---

<section class="aw-hero" markdown>

# Know when your AI coding assistant needs you

<p class="aw-lead">AgentWatch watches Claude Code, Cursor, Codex and other AI coding
assistants while they work. It tells you when one is going in circles, keeps failing,
is burning through money, or is doing something risky with your passwords, keys or
data.</p>

<p class="aw-actions" markdown>
[Get started](get-started.md){ .md-button .md-button--primary }
[See what it checks](what-it-checks.md){ .aw-textlink }
</p>

</section>

<figure class="aw-shot" markdown>
<a href="assets/images/dashboard.svg" class="aw-shot__frame" title="Open the screenshot full size">
<img src="assets/images/dashboard.svg" width="1219" height="633" alt="The AgentWatch dashboard listing four coding sessions. At the top, checkout-api, a Claude Code session, has health 69%, its context 86% full, and the warning 'loop: Bash (7x)'. Below it, newsletter has the warning 'credential access'. photo-gallery, a Codex session, and recipe-app show ok. The details panel for checkout-api lists 'Repeated action: Bash (7x)' with the error it keeps getting, and the Events panel shows newsletter's 'credential access' and 'upload' warnings arriving.">
</a>
<figcaption>The live dashboard (<code>agentwatch watch-all --security</code>) with four
made-up sessions: one stuck re-running a failing command, one that read a password
file and uploaded it, and two working normally.</figcaption>
</figure>

<section class="aw-section" markdown>

## What it watches for

<div class="aw-groups" markdown>

<div class="aw-group" markdown>

### :octicons-pulse-24: Wasted time and money

- **Going in circles.** It runs the same command, gets the same error, and runs it
  again.
- **Failing over and over.** Step after step fails, and nothing works in between.
- **Stuck, no progress.** It keeps reading and searching files but never changes
  anything.
- **Forgetting earlier work.** Its memory (the *context window*: how much of the
  conversation it can hold at once) fills up, and it goes back to files it already
  read.
- **Burning money.** AI services charge by the *token*, a few characters of text.
  AgentWatch estimates what each session has cost so far, and how much of that
  went on steps that led nowhere.

</div>

<div class="aw-group" markdown>

### :octicons-shield-lock-24: Security

- **Leaked passwords and keys.** An API key (a password for an online service)
  shows up in a command the assistant ran or in what it wrote.
- **Prompt injection.** Hidden instructions in a file or web page try to take over
  the assistant, such as "ignore your previous instructions".
- **Data sent somewhere unexpected.** It opens your `.env` file, where passwords
  are often kept, and then sends data to a server.
- **Dangerous commands.** It deletes files in bulk, or gives itself administrator
  rights with `sudo`.
- **Unknown add-ons.** A new *skill* (an add-on that gives the assistant new
  abilities) is installed, or starts connecting to the internet.

</div>

</div>

</section>

<section class="aw-section" markdown>

## How it works

<ol class="aw-steps">
<li class="aw-step">
<h3>Install it</h3>
<p>One command in a terminal: <code>pipx install agentwatch-monitor</code>. You need
Python 3.11 or newer. The <a href="get-started/">Get started</a> page walks you
through it on Mac, Windows and Linux.</p>
</li>
<li class="aw-step">
<h3>Run it next to your assistant</h3>
<p>In a second terminal window, run <code>agentwatch watch-all</code>. It finds the
assistants running on your computer by itself and follows each session as it
works.</p>
</li>
<li class="aw-step">
<h3>Read the score</h3>
<p>Every session gets a health score from 0 to 100 and a list of what is wrong, in
plain words. Add <code>--security</code>, or press <kbd>s</kbd>, to get a security
verdict too.</p>
</li>
</ol>

<div class="aw-scale">
<p class="aw-scale__title" id="health-scale">The health score, from 0 to 100</p>
<div class="aw-scale__track">
<ol class="aw-scale__bands" aria-labelledby="health-scale">
<li class="aw-band aw-band--bad"><span class="aw-band__word">Stuck</span> <span class="aw-band__range">0–39</span></li>
<li class="aw-band aw-band--warn"><span class="aw-band__word">Spinning</span> <span class="aw-band__range">40–59</span></li>
<li class="aw-band aw-band--degraded"><span class="aw-band__word">Struggling</span> <span class="aw-band__range">60–79</span></li>
<li class="aw-band aw-band--ok"><span class="aw-band__word">Productive</span> <span class="aw-band__range">80–100</span></li>
</ol>
<p class="aw-scale__marker" style="--at: 69" aria-hidden="true">checkout-api, 69</p>
</div>
<p class="aw-scale__note">In the screenshot above, checkout-api scores 69: struggling.
These are AgentWatch's own words for each range; if you prefer healthy, degraded,
warning and critical, add <code>--theme classic</code>.</p>
<p class="aw-scale__note">The security verdict is separate:
<span class="aw-chip aw-chip--ok">Secure</span> when nothing is found (100),
<span class="aw-chip aw-chip--degraded">At risk</span> from 50 to 99, and
<span class="aw-chip aw-chip--bad">Compromised</span> below 50. One critical finding,
such as a password file being read and then sent over the network, means
compromised.</p>
</div>

</section>

<section class="aw-section aw-private" markdown>

<div class="aw-private__intro" markdown>

## Private by design

Your assistant already keeps a log of everything it does. AgentWatch reads that
log on your own computer, and that is all it needs.

</div>

<ul class="aw-facts">
<li><strong>Runs on your computer.</strong> There is no AgentWatch server and no
account to create.</li>
<li><strong>Your code stays with you.</strong> Nothing from your code or your
conversations is sent anywhere. Its only network use is looking up server names, and
alerts you choose to set up (<a href="faq/#does-it-send-my-data-anywhere">details</a>).</li>
<li><strong>No AI in the checks.</strong> They are plain rules, so they cost nothing
to run and give the same answer every time.</li>
<li><strong>Free and open source.</strong> MIT license. Anyone can read the code on
<a href="https://github.com/LoomLabs-Venture-Studio/agentwatch">GitHub</a>.</li>
</ul>

</section>

<section class="aw-section aw-end" markdown>

<p class="aw-works" markdown>**Works with** Claude Code, Cursor, Codex, the ChatGPT desktop
app, GitHub Copilot, Aider, Gemini CLI, Cline, OpenCode and more.
[See which are fully tested](supported-agents.md).</p>

[Get started](get-started.md){ .md-button .md-button--primary }

</section>
