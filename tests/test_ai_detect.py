"""Tests for agentwatch.ai_detect (machine-wide AI-use detection).

Every OS/network call is a fake: no real DNS, sockets or processes.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace

import psutil

from agentwatch.ai_detect import detect

IPS = {
    "api.anthropic.com": "160.79.104.10",
    "claude.ai": "160.79.104.10",  # shared IP, same provider
    "api.openai.com": "162.159.140.245",
    "chatgpt.com": "104.18.32.47",
}


def fake_resolve(domain, port):
    if domain not in IPS:
        raise socket.gaierror(f"no such host {domain}")
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (IPS[domain], port))]


def conn(pid, rip=None, lport=None, status="ESTABLISHED"):
    return SimpleNamespace(
        pid=pid,
        raddr=SimpleNamespace(ip=rip, port=443) if rip else (),
        laddr=SimpleNamespace(ip="127.0.0.1", port=lport or 50000),
        status=status,
    )


class FakeProc:
    def __init__(self, pid, name, exe=None, cmdline=None, deny_exe=False, gone=False):
        self.pid, self._name, self._exe = pid, name, exe
        self._cmdline = cmdline if cmdline is not None else ([exe] if exe else [])
        self._deny_exe, self._gone = deny_exe, gone

    def name(self):
        if self._gone:
            raise psutil.NoSuchProcess(self.pid)
        return self._name

    def exe(self):
        if self._deny_exe:
            raise psutil.AccessDenied(self.pid)
        return self._exe

    def cmdline(self):
        return self._cmdline


def run(conns, procs, resolve=fake_resolve):
    table = {p.pid: p for p in procs}
    return detect(
        resolve=resolve,
        connections=lambda kind: conns,
        process_iter=lambda: list(table.values()),
        process=lambda pid: table[pid],
    )


def test_attributes_provider_and_counts_connections():
    r = run(
        [conn(10, "160.79.104.10"), conn(10, "160.79.104.10")],
        [FakeProc(10, "Orca.exe", r"C:\Apps\Orca\Orca.exe")],
    )
    [u] = r.usages
    assert (u.pid, u.name, u.providers, u.connections) == (10, "Orca.exe", {"anthropic"}, 2)
    assert u.adapter is None


def test_ignores_non_ai_connections_and_missing_pids():
    r = run(
        [conn(10, "1.1.1.1"), conn(None, "160.79.104.10"), conn(0, "160.79.104.10")],
        [FakeProc(10, "app.exe")],
    )
    assert r.usages == []


def test_ipv4_mapped_ipv6_remote_matches():
    r = run([conn(10, "::ffff:160.79.104.10")], [FakeProc(10, "Orca.exe")])
    assert r.usages[0].providers == {"anthropic"}


def test_browsers_excluded_case_insensitive():
    r = run(
        [conn(1, "160.79.104.10"), conn(2, "104.18.32.47"), conn(3, "104.18.32.47")],
        [FakeProc(1, "Brave.exe"), FakeProc(2, "CHROME.EXE"), FakeProc(3, "firefox")],
    )
    assert r.usages == []


def test_one_row_per_pid_for_multiprocess_apps():
    r = run(
        [conn(1, "104.18.32.47"), conn(2, "104.18.32.47")],
        [FakeProc(1, "ChatGPT.exe"), FakeProc(2, "ChatGPT.exe")],
    )
    assert sorted(u.pid for u in r.usages) == [1, 2]


def test_maps_supported_agent_and_sorts_unsupported_first():
    r = run(
        [conn(1, "160.79.104.10"), conn(2, "160.79.104.10")],
        [
            FakeProc(1, "claude.exe", r"C:\Users\x\.local\bin\claude.exe"),
            FakeProc(2, "Orca.exe", r"C:\Apps\Orca\Orca.exe"),
        ],
    )
    assert [(u.name, u.adapter) for u in r.usages] == [
        ("Orca.exe", None),
        ("claude.exe", "claude-code"),
    ]


def test_vanished_process_skipped_and_denied_exe_is_none():
    r = run(
        [conn(1, "160.79.104.10"), conn(2, "160.79.104.10")],
        [FakeProc(1, "gone.exe", gone=True), FakeProc(2, "Orca.exe", deny_exe=True)],
    )
    [u] = r.usages
    assert (u.pid, u.exe) == (2, None)


def test_unresolvable_domains_reported():
    r = run([], [])
    assert "api.anthropic.com" not in r.unresolved
    assert "api.mistral.ai" in r.unresolved


def test_ollama_listener_counted_when_name_matches():
    r = run(
        [conn(5, lport=11434, status="LISTEN")],
        [FakeProc(5, "ollama.exe", r"C:\Ollama\ollama.exe")],
    )
    [u] = r.usages
    assert (u.local_runtime, u.connections, u.providers) == ("ollama", 0, set())


def test_llm_port_owned_by_unrelated_process_ignored():
    r = run([conn(5, lport=11434, status="LISTEN")], [FakeProc(5, "node.exe")])
    assert r.usages == []


def test_access_denied_falls_back_per_process_and_marks_partial():
    class Proc(FakeProc):
        def net_connections(self, kind):
            if self.pid == 2:
                raise psutil.AccessDenied(self.pid)
            return [conn(None, "160.79.104.10")]

    table = {1: Proc(1, "Orca.exe"), 2: Proc(2, "secret.exe")}

    def denied(kind):
        raise psutil.AccessDenied()

    r = detect(
        resolve=fake_resolve,
        connections=denied,
        process_iter=lambda: list(table.values()),
        process=lambda pid: table[pid],
    )
    assert r.partial is True
    assert [u.pid for u in r.usages] == [1]


def test_google_front_end_ips_not_attributed():
    # generativelanguage.googleapis.com shares IPs with every googleapis.com
    # service (Drive, sign-in), so a Google connection proves nothing.
    ips = {**IPS, "generativelanguage.googleapis.com": "172.217.112.4"}

    def resolve(domain, port):
        if domain not in ips:
            raise socket.gaierror(domain)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ips[domain], port))]

    r = run([conn(10, "172.217.112.4")], [FakeProc(10, "GoogleDriveFS.exe")], resolve)
    assert r.usages == []


def test_unowned_ai_connection_marks_partial():
    # Linux: other users' sockets come back with pid=None, no AccessDenied.
    r = run([conn(None, "160.79.104.10")], [])
    assert r.partial is True


def test_unowned_non_ai_connection_not_partial():
    r = run([conn(None, "1.1.1.1"), conn(0, "160.79.104.10")], [])
    assert r.partial is False


def test_oserror_on_global_table_falls_back_and_marks_partial():
    def denied(kind):
        raise PermissionError("/proc/net restricted")

    r = detect(
        resolve=fake_resolve,
        connections=denied,
        process_iter=lambda: [],
        process=lambda pid: None,
    )
    assert r.partial is True and r.usages == []


def test_oserror_on_exe_treated_like_access_denied():
    class Proc(FakeProc):
        def exe(self):
            raise OSError(299, "partial copy")

    r = run([conn(1, "160.79.104.10")], [Proc(1, "Orca.exe")])
    assert (r.usages[0].pid, r.usages[0].exe) == (1, None)
