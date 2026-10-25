"""Tests for agentwatch.ai_detect (machine-wide AI-use detection).

Every OS/network call is a fake: no real DNS, sockets or processes.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace

import psutil
import pytest

from agentwatch import agents
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


@pytest.fixture(autouse=True)
def no_editor_sessions(monkeypatch):
    """Editor discovery reads real stores; default every editor adapter to idle."""
    calls = []
    for a in agents.editor_adapters():
        monkeypatch.setattr(a, "discover", lambda n=a.name: calls.append(n) or [])
    return calls


def live(monkeypatch, name, *commands):
    """Give adapter *name* live sessions with these AgentProcess.command values."""
    sessions = [SimpleNamespace(command=c) for c in commands]
    monkeypatch.setattr(agents.get(name), "discover", lambda: sessions)


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


def test_editor_processes_map_to_editor_adapters():
    r = run(
        [conn(1, "160.79.104.10"), conn(2, "160.79.104.10")],
        [FakeProc(1, "Code.exe", r"C:\x\Code.exe"), FakeProc(2, "Cursor.exe", r"C:\x\Cursor.exe")],
    )
    assert sorted(u.adapter for u in r.usages) == ["copilot-vscode", "cursor"]


def code():
    return run([conn(1, "160.79.104.10")], [FakeProc(1, "Code.exe", r"C:\x\Code.exe")])


@pytest.mark.parametrize("command", ["vscode (cline)", "cline (vscode)"])
def test_code_with_only_cline_live_is_cline(monkeypatch, command):
    # #119: legacy-store task, or SDK-store session with source "vscode".
    live(monkeypatch, "cline", command)
    assert code().usages[0].adapter == "cline"


def test_code_with_cline_cli_session_only_keeps_default(monkeypatch):
    # A Cline CLI session doesn't run inside VS Code.
    live(monkeypatch, "cline", "cline (cli)")
    assert code().usages[0].adapter == "copilot-vscode"


def test_code_with_both_live_lists_both_in_registry_order(monkeypatch):
    live(monkeypatch, "cline", "vscode (cline)")
    live(monkeypatch, "copilot-vscode", "vscode (copilot)")
    assert code().usages[0].adapter == "copilot-vscode, cline"


def cursor():
    return run([conn(2, "160.79.104.10")], [FakeProc(2, "Cursor.exe", r"C:\x\Cursor.exe")])


def test_cursor_with_live_cline_task_is_cursor_and_cline(monkeypatch):
    # #127: Cline's legacy store is read for Cursor since #124.
    live(monkeypatch, "cline", "cursor (cline)")
    live(monkeypatch, "cursor", "cursor")
    assert cursor().usages[0].adapter == "cursor, cline"


def test_cursor_without_cline_task_is_cursor():
    assert cursor().usages[0].adapter == "cursor"


@pytest.mark.parametrize("command", ["vscode (cline)", "cline (vscode)"])
def test_stable_code_cline_sessions_not_credited_to_cursor(monkeypatch, command):
    live(monkeypatch, "cline", command)
    assert cursor().usages[0].adapter == "cursor"


def test_cursor_cline_session_not_credited_to_stable_code(monkeypatch):
    live(monkeypatch, "cline", "cursor (cline)")
    assert code().usages[0].adapter == "copilot-vscode"


@pytest.mark.parametrize(
    "name", ["Code - Insiders.exe", "code-insiders", "Code - Insiders", "VSCodium.exe", "codium"]
)
def test_insiders_and_vscodium_processes_are_cline(name, no_editor_sessions):
    # Cline is the only adapter for these editors: labelled without discovery.
    r = run([conn(3, "160.79.104.10")], [FakeProc(3, name)])
    assert r.usages[0].adapter == "cline"
    assert no_editor_sessions == []


def test_editor_discovery_raising_falls_back(monkeypatch):
    def boom():
        raise RuntimeError("store unreadable")

    monkeypatch.setattr(agents.get("copilot-vscode"), "discover", boom)
    monkeypatch.setattr(agents.get("cline"), "discover", boom)
    assert code().usages[0].adapter == "copilot-vscode"
    live(monkeypatch, "cline", "vscode (cline)")
    assert code().usages[0].adapter == "cline"


def test_editor_discovery_once_per_run_and_only_when_needed(no_editor_sessions):
    run([conn(1, "160.79.104.10")], [FakeProc(1, "Orca.exe")])
    assert no_editor_sessions == []
    run(
        [conn(1, "160.79.104.10"), conn(2, "160.79.104.10")],
        [FakeProc(1, "Code.exe"), FakeProc(2, "code")],
    )
    assert sorted(no_editor_sessions) == ["cline", "copilot-vscode"]


def test_cline_discovered_once_across_editors(no_editor_sessions):
    run(
        [conn(1, "160.79.104.10"), conn(2, "160.79.104.10"), conn(3, "160.79.104.10")],
        [FakeProc(1, "Code.exe"), FakeProc(2, "Cursor.exe"), FakeProc(3, "cursor")],
    )
    assert sorted(no_editor_sessions) == ["cline", "copilot-vscode", "cursor"]


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


@pytest.mark.parametrize("name, port, runtime", [
    ("LM Studio.exe", 1234, "lm-studio"),
    ("LM Studio", 1234, "lm-studio"),
    ("lm-studio", 1234, "lm-studio"),
    ("LM Studio Helper (Renderer)", 1234, "lm-studio"),
    ("Ollama", 11434, "ollama"),
    ("ollama app.exe", 11434, "ollama"),
    ("llama-server.exe", 9931, "llama.cpp"),
    ("Jan-Desktop.exe", 1337, "jan"),
])
def test_table_runtimes_labelled_by_port_and_name(name, port, runtime):
    r = run([conn(5, lport=port, status="LISTEN")], [FakeProc(5, name)])
    assert r.usages[0].local_runtime == runtime


def test_runtime_name_on_another_runtimes_port_ignored():
    r = run([conn(5, lport=1234, status="LISTEN")], [FakeProc(5, "ollama.exe")])
    assert r.usages == []


def test_llama_cpp_python_listener_needs_cmdline_gate():
    gated = FakeProc(5, "python.exe", cmdline=["python", "-m", "llama_cpp.server"])
    assert run([conn(5, lport=8000, status="LISTEN")], [gated]).usages[0].local_runtime == (
        "llama-cpp-python")
    plain = FakeProc(5, "python.exe", cmdline=["python", "-m", "http.server"])
    assert run([conn(5, lport=8000, status="LISTEN")], [plain]).usages == []


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


def test_version_named_binary_shows_adapter_display_name():
    """Claude Code's native binary is named after its version (`versions/2.1.310`)."""
    r = run(
        [conn(1, "160.79.104.10")],
        [FakeProc(1, "2.1.310", "/home/dev/.local/share/claude/versions/2.1.310")],
    )
    [u] = r.usages
    assert u.name == "2.1.310"  # raw OS name is kept
    assert u.adapter == "claude-code"
    assert u.display_name == "claude-code"


@pytest.mark.parametrize(
    ("name", "exe", "adapter", "expected"),
    [
        ("2.1.310", "/opt/acme/bin/2.1.310", None, "bin"),  # no adapter: exe's parent dir
        ("2.1.310", "/opt/acme/2.1.310", "acme-agent", "acme-agent"),  # adapter wins
        ("2.1.310", "/opt/1.0/2.1.310", None, "2.1.310"),  # parent is a version too
        ("2.1.310", None, None, "2.1.310"),  # no exe and no adapter: keep the name
        ("Orca.exe", "/apps/Orca/Orca.exe", None, "Orca.exe"),  # not version-like
        ("claude", "/x/claude", "claude-code", "claude"),  # not version-like
    ],
)
def test_display_name_only_replaces_version_like_names(name, exe, adapter, expected):
    from agentwatch.ai_detect import AiUsage

    assert AiUsage(pid=1, name=name, exe=exe, adapter=adapter).display_name == expected
