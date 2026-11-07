"""Severity for a ``c2_beacon`` text match.

Detection is unchanged: ``C2CommunicationDetector`` flags any command that
matches one of its three text rules, and every match is still reported.
This module only chooses the severity of that finding, with cheap regexes
over the matched text -- no shell parsing, so it cannot be desynchronised
by a crafted here-document, quoting or wrapper.

``beacon_severity(command)`` returns CRITICAL unless the command is plainly
a local readiness probe. It is HIGH only when every URL/host token is a
literal loopback target (``localhost``, ``127.x.x.x``, ``[::1]`` or
``0.0.0.0`` with an optional ``:port`` and path) and none of these
"beacon" markers appear:

- a loop keyword (``while``/``until``/``for``/``select``/``repeat``) or
  ``cron``/``crontab``
- a network tool (``nc``/``ncat``/``netcat``)
- a pipe into a shell or interpreter (``| sh``, ``| python`` ...)
- running code: a shell/interpreter with a script argument, ``./prog``,
  ``chmod +x``, or an installer (``npx``/``uvx``/``pip install`` ...)
- command substitution (``$(...)`` or backticks)
- ``.curlrc`` or a ``PATH=`` assignment (config/search-path hijack)
- any non-loopback URL or ``host:port`` token

Anything the markers do not cover, or any host that is not a clean literal
loopback, stays CRITICAL. The default is always CRITICAL (fail safe).
"""

from __future__ import annotations

import re

from ..base import Severity

# A clean, literal loopback target: scheme optional, port optional, path
# optional, and it must end at a delimiter -- so "127.0.0.1@evil",
# "127.0.0.1%2eevil" and "localhost.evil" do NOT match here (they are left
# for the remote-host check below).
_LOOPBACK = re.compile(
    r"(?i)(?<![\w.@%+/-])(?:https?://)?"
    r"(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|0\.0\.0\.0)"
    r"(?::\d{1,5})?"
    r"(?:[/?#][^\s'\"|;&)]*)?"
    r"(?=[\s'\"|;&)<>]|$)"
)
# Any scheme URL, and any host:port, that survives loopback stripping.
_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s'\"|;&<>)]+")
_HOSTPORT = re.compile(r"(?i)(?<![\w.:/@-])[a-z0-9][a-z0-9.-]*:\d{1,5}(?![\d.])")

_LOOP = re.compile(r"(?i)\b(?:while|until|for|select|repeat|foreach)\b")
_CRON = re.compile(r"(?i)\bcron")
_NET_TOOL = re.compile(r"(?i)\b(?:nc|ncat|netcat)\b")
_SUBST = re.compile(r"\$\(|`")
_CONFIG_HIJACK = re.compile(r"(?i)\.curlrc|(?:^|[\s;&|(])PATH=")

_INTERP = (r"sh|bash|zsh|dash|ash|ksh|fish|csh|tcsh|python[0-9.]*|perl|ruby|"
           r"node|nodejs|deno|bun|php|lua|eval|source")
_PIPE_SHELL = re.compile(
    r"(?i)\|\s*(?:\w+=\S*\s+|sudo\s+|nohup\s+|command\s+|exec\s+|env\s+|"
    r"time\s+|stdbuf\s+\S+\s+|xargs(?:\s+-\S+)*\s+|timeout\s+\S+\s+)*"
    r"(?:" + _INTERP + r")\b"
)
# Running code: a shell/interpreter with a script argument, an executable
# invoked directly, chmod +x, or an installer that runs fetched code. A
# readiness probe does none of these (it only curls and reads the status).
_RUN_CODE = re.compile(
    r"(?i)(?:\b(?:sh|bash|zsh|dash|ash|ksh|python[0-9.]*|perl|ruby|node|"
    r"nodejs|deno|bun|php|lua)\b[ \t]+\S|chmod[ \t]+\+?x|"
    r"chmod[ \t]+[0-7]*[1357]\b|(?:^|[\s;&|(])\./\S|"
    r"\b(?:npx|uvx|pipx)\b|\b(?:pip[0-9.]*|npm|pnpm|yarn|gem|cargo|go)\b"
    r"[ \t]+install\b|\bsource\b[ \t]+\S)"
)


def _has_remote_host(command: str) -> bool:
    """A URL or host:port that is not a clean literal loopback target."""
    stripped = _LOOPBACK.sub(" ", command)
    return bool(_URL.search(stripped) or _HOSTPORT.search(stripped))


def _is_local_probe(command: str) -> bool:
    if not _LOOPBACK.search(command):
        return False       # no loopback target -> not a readiness probe
    if (_LOOP.search(command) or _CRON.search(command)
            or _NET_TOOL.search(command) or _SUBST.search(command)
            or _CONFIG_HIJACK.search(command) or _PIPE_SHELL.search(command)
            or _RUN_CODE.search(command)):
        return False
    return not _has_remote_host(command)


def beacon_severity(command: str) -> Severity:
    """Severity of a c2_beacon match: HIGH for a local probe, else CRITICAL."""
    return Severity.HIGH if _is_local_probe(command) else Severity.CRITICAL


def beacon_exempt(command: str) -> bool:
    """Deprecated: nothing is exempt now; a match is always a finding."""
    return False
