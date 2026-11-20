"""find_running_agents() and friends must be safe to call from many threads.

psutil.process_iter(attrs=...) writes onto Process objects shared across
threads, so concurrent scans used to hit ``KeyError: 'pid'`` (the visual
server polls from a ThreadingHTTPServer). These tests use real psutil.
"""

from __future__ import annotations

import threading

from agentwatch import cursor_discovery, discovery

THREADS = 16
ROUNDS = 6


def _hammer(fn) -> list[BaseException]:
    errors: list[BaseException] = []
    barrier = threading.Barrier(THREADS)

    def run():
        barrier.wait()
        for _ in range(ROUNDS):
            try:
                fn()
            except BaseException as exc:  # noqa: BLE001 - collect everything
                errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return errors


def test_find_running_agents_concurrent():
    assert _hammer(discovery.find_running_agents) == []


def test_find_running_agents_with_cursor_scan_concurrent():
    """Half the threads also run the cursor process check (attrs=['name'])."""
    counter = iter(range(10**9))
    lock = threading.Lock()

    def mixed():
        with lock:
            n = next(counter)
        if n % 2:
            cursor_discovery.is_cursor_running()
        else:
            discovery.find_running_agents()

    assert _hammer(mixed) == []
