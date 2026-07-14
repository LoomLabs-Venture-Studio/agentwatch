#!/usr/bin/env python3
"""Simulate a session that progressively rots — exercises all five metric modules.

Usage:
    # Terminal 1: Start the simulation
    python tests/simulate_rot.py /tmp/rot_test.jsonl

    # Terminal 2: Watch it degrade in real time
    agentwatch watch --log /tmp/rot_test.jsonl
"""

import json
import sys
import time
from datetime import datetime, timedelta, timezone

LOG_PATH = sys.argv[1] if len(sys.argv) > 1 else "/tmp/rot_test.jsonl"


def ts(dt: datetime) -> str:
    return dt.isoformat()


def emit(f, entry: dict, label: str = ""):
    f.write(json.dumps(entry) + "\n")
    f.flush()
    if label:
        print(f"  -> {label}")


def assistant_entry(t: datetime, text: str, tool_name: str, tool_input: dict, sid: str = "sim-session") -> dict:
    """Build a Claude Code-style assistant message with text + tool_use."""
    return {
        "type": "assistant",
        "timestamp": ts(t),
        "sessionId": sid,
        "message": {
            "role": "assistant",
            "content": [
                {"type": "text", "text": text},
                {"type": "tool_use", "name": tool_name, "input": tool_input},
            ],
        },
    }


def tool_result_entry(t: datetime, is_error: bool = False, content: str = "", sid: str = "sim-session") -> dict:
    """Build a Claude Code-style user message with tool_result."""
    return {
        "type": "user",
        "timestamp": ts(t),
        "sessionId": sid,
        "message": {
            "role": "user",
            "content": [
                {"type": "tool_result", "is_error": is_error, "content": content},
            ],
        },
    }


def main():
    print(f"Writing simulated rot log to: {LOG_PATH}")
    print(f"Run in another terminal:  agentwatch watch --log {LOG_PATH}")
    print()

    now = datetime.now(timezone.utc)
    offset = 0

    def tick(seconds: int = 3) -> datetime:
        nonlocal offset
        offset += seconds
        return now + timedelta(seconds=offset)

    with open(LOG_PATH, "w") as f:
        # -----------------------------------------------------------
        # Phase 1: Healthy productive work (edits + passing tests)
        # -----------------------------------------------------------
        print("== Phase 1: Healthy productive work ==")
        for i in range(5):
            t = tick(5)
            emit(f, assistant_entry(t, f"I'll update module_{i}.py to fix the handler.",
                                    "Edit", {"file_path": f"src/module_{i}.py"}),
                 f"edit src/module_{i}.py")
            time.sleep(0.8)

            t = tick(3)
            emit(f, assistant_entry(t, "Let me run the tests.",
                                    "Bash", {"command": "pytest tests/"}),
                 "bash pytest (pass)")
            t = tick(2)
            emit(f, tool_result_entry(t, is_error=False, content="All 12 tests passed"),
                 "  result: pass")
            time.sleep(0.8)

        # -----------------------------------------------------------
        # Phase 2: Behavioral degradation (hedging + apologies)
        # -----------------------------------------------------------
        print()
        print("== Phase 2: Hedging and apologising ==")
        hedge_texts = [
            "I'm sorry, I might have made a mistake earlier. Perhaps I should maybe re-examine this. Let me possibly try a different approach, although I'm not entirely sure it will work. I apologize for the confusion.",
            "Actually, I apologize, that was incorrect. Maybe I should probably look at this from a different angle. Perhaps the issue is likely somewhere else. I'm sorry for the mistake.",
            "Let me correct my earlier mistake. I apologize — I was wrong about the import. Perhaps it should possibly be a different module. I'm sorry, let me try again with a presumably better approach.",
            "I'm sorry about that. Maybe perhaps I should likely reconsider. Possibly the issue is approximately related to the config. My apologies, let me presumably try something different.",
        ]
        for i, text in enumerate(hedge_texts):
            t = tick(8)
            emit(f, assistant_entry(t, text, "Read", {"file_path": "src/config.py"}),
                 f"hedging turn {i}")
            time.sleep(1.2)

        # -----------------------------------------------------------
        # Phase 3: Repetition (same sentences across turns)
        # -----------------------------------------------------------
        print()
        print("== Phase 3: Repetitive output ==")
        repeated_text = "The issue is in the database connection handler. We need to update the retry logic in the connection pool. The timeout parameter should be increased to handle slow queries."
        for i in range(5):
            t = tick(6)
            emit(f, assistant_entry(t, repeated_text, "Read", {"file_path": "src/db.py"}),
                 f"repeated output {i}")
            time.sleep(1.0)

        # -----------------------------------------------------------
        # Phase 4: Tool thrash (same command failing repeatedly)
        # -----------------------------------------------------------
        print()
        print("== Phase 4: Tool thrash — same failing command ==")
        for i in range(10):
            t = tick(4)
            emit(f, assistant_entry(t, f"Let me try running the tests again (attempt {i+1}).",
                                    "Bash", {"command": "npm test"}),
                 f"bash npm test (fail #{i+1})")
            t = tick(2)
            emit(f, tool_result_entry(t, is_error=True, content="FAIL: TypeError: Cannot read property 'map' of undefined"),
                 "  result: FAIL")
            time.sleep(1.0)

        # -----------------------------------------------------------
        # Phase 5: Progress stall (reads only, no edits)
        # -----------------------------------------------------------
        print()
        print("== Phase 5: Progress stall — reading without editing ==")
        for i in range(8):
            t = tick(5)
            emit(f, assistant_entry(t, f"Let me look at file {i} to understand the issue better.",
                                    "Read", {"file_path": f"src/handler_{i % 3}.py"}),
                 f"read src/handler_{i % 3}.py (stalling)")
            time.sleep(1.0)

        # -----------------------------------------------------------
        # Phase 6: File churn (same file edited repeatedly, tests fail)
        # -----------------------------------------------------------
        print()
        print("== Phase 6: File churn — editing same file, always failing ==")
        for i in range(6):
            t = tick(4)
            emit(f, assistant_entry(t, f"Fix attempt {i+1} on app.py.",
                                    "Edit", {"file_path": "src/app.py"}),
                 f"edit src/app.py (attempt {i+1})")
            t = tick(3)
            emit(f, assistant_entry(t, "Running tests.",
                                    "Bash", {"command": "pytest tests/test_app.py"}),
                 "bash pytest (fail)")
            t = tick(2)
            emit(f, tool_result_entry(t, is_error=True, content="FAIL: AssertionError: expected 200 got 500"),
                 "  result: FAIL")
            time.sleep(1.0)

        print()
        print("== Done. Log remains open for live monitoring. ==")
        print("   Press Ctrl+C to stop.")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
