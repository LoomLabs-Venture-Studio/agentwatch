#!/usr/bin/env python3
"""Simulate an agent stuck in a loop by appending log entries over time.

Usage:
    # Terminal 1: Start the simulation
    python tests/simulate_loop.py /tmp/loop_test.jsonl

    # Terminal 2: Watch it degrade in real time
    agentwatch watch --log /tmp/loop_test.jsonl
"""

import json
import sys
import time
from datetime import datetime, timedelta, timezone

LOG_PATH = sys.argv[1] if len(sys.argv) > 1 else "/tmp/loop_test.jsonl"


def ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def emit(f, entry: dict):
    f.write(json.dumps(entry) + "\n")
    f.flush()
    print(f"  -> {entry.get('tool', '?'):6}  success={entry.get('success')}  {entry.get('error', entry.get('file', entry.get('command', '')))}")


def main():
    print(f"Writing simulated loop log to: {LOG_PATH}")
    print(f"Run in another terminal:  agentwatch watch --log {LOG_PATH}")
    print()

    now = datetime.now(timezone.utc)

    with open(LOG_PATH, "w") as f:
        # Phase 1: Normal healthy work (5 entries)
        print("== Phase 1: Normal healthy work ==")
        for i in range(5):
            t = now + timedelta(seconds=i * 5)
            emit(f, {"timestamp": ts(t), "tool": "read", "file": f"src/module_{i}.py", "success": True})
            time.sleep(1)

        emit(f, {"timestamp": ts(now + timedelta(seconds=25)), "tool": "edit", "file": "src/module_0.py", "success": True})
        time.sleep(1)

        emit(f, {"timestamp": ts(now + timedelta(seconds=30)), "tool": "bash", "command": "python -m pytest tests/", "success": True})
        time.sleep(1)

        print()
        print("== Phase 2: Starting to re-read same file ==")
        # Phase 2: Re-reading same file (reread detector should trigger)
        for i in range(6):
            t = now + timedelta(seconds=35 + i * 5)
            emit(f, {"timestamp": ts(t), "tool": "read", "file": "src/app.py", "success": True})
            time.sleep(1.5)

        print()
        print("== Phase 3: Edit-test-fail loop (thrash) ==")
        # Phase 3: Edit -> bash fail -> edit -> bash fail (thrash detector)
        for i in range(5):
            t = now + timedelta(seconds=65 + i * 10)
            emit(f, {"timestamp": ts(t), "tool": "edit", "file": "src/app.py", "success": True})
            time.sleep(1)
            emit(f, {"timestamp": ts(t + timedelta(seconds=5)), "tool": "bash", "command": "python test.py", "success": False, "error": "SyntaxError: unexpected indent"})
            time.sleep(1.5)

        print()
        print("== Phase 4: Identical repeated commands (loop detector) ==")
        # Phase 4: Exact same bash command repeated (loop detector)
        for i in range(8):
            t = now + timedelta(seconds=115 + i * 5)
            emit(f, {"timestamp": ts(t), "tool": "bash", "command": "npm run build", "success": False, "error": "Error: Cannot find module './config'"})
            time.sleep(1.5)

        print()
        print("== Phase 5: Syntax error spiral ==")
        # Phase 5: Repeated syntax/import errors (syntax_loop detector)
        errors = [
            "ImportError: No module named 'foo'",
            "ImportError: No module named 'foo'",
            "ModuleNotFoundError: No module named 'bar'",
            "NameError: name 'baz' is not defined",
            "SyntaxError: invalid syntax",
            "SyntaxError: invalid syntax",
        ]
        for i, err in enumerate(errors):
            t = now + timedelta(seconds=155 + i * 5)
            emit(f, {"timestamp": ts(t), "tool": "bash", "command": "python main.py", "success": False, "error": err})
            time.sleep(1.5)

        print()
        print("== Done. Log file will stay open for monitoring. ==")
        print("   Press Ctrl+C to stop.")

        # Keep file open so watcher stays active
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
