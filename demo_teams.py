#!/usr/bin/env python3
"""Demo: 2 teams, each root + 3 sub-agents, all generating live log activity.

Team 1 — "ecommerce-platform" (claude-code)
  root:  Orchestrator — delegates tasks, reads plans, runs integration tests
  sub-1: Frontend agent — builds React components, mostly healthy
  sub-2: Backend agent — writing API routes, hitting DB errors
  sub-3: Test agent — running tests in a loop, stuck on flaky test

Team 2 — "ml-pipeline" (claude-code)
  root:  ML lead — reading data, training models, healthy
  sub-1: Data prep agent — cleaning CSVs, occasional errors
  sub-2: Model agent — hyperparameter tuning, looping on same config
  sub-3: Deploy agent — fighting docker/k8s issues, error spiral

Usage:
    .venv/bin/python demo_teams.py
"""

from __future__ import annotations

import json
import random
import shutil
import tempfile
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path

DEMO_DIR = Path(tempfile.mkdtemp(prefix="agentwatch_demo_"))

# ── Agent definitions ─────────────────────────────────────────────────────

AGENTS = {
    # ═══ Team 1: ecommerce-platform ═══
    "ecom_root": {
        "pid": 80000, "type": "claude-code", "project": "ecommerce-platform",
        "depth": 0, "parent_agent_pid": None, "team_id": 80000,
        "log": DEMO_DIR / "ecom_root.jsonl",
        "scenario": "orchestrator",
    },
    "ecom_frontend": {
        "pid": 80100, "type": "claude-code", "project": "ecommerce-platform",
        "depth": 1, "parent_agent_pid": 80000, "team_id": 80000,
        "log": DEMO_DIR / "ecom_frontend.jsonl",
        "scenario": "frontend_dev",
    },
    "ecom_backend": {
        "pid": 80200, "type": "claude-code", "project": "ecommerce-platform",
        "depth": 1, "parent_agent_pid": 80000, "team_id": 80000,
        "log": DEMO_DIR / "ecom_backend.jsonl",
        "scenario": "backend_errors",
    },
    "ecom_tests": {
        "pid": 80300, "type": "claude-code", "project": "ecommerce-platform",
        "depth": 1, "parent_agent_pid": 80000, "team_id": 80000,
        "log": DEMO_DIR / "ecom_tests.jsonl",
        "scenario": "flaky_tests",
    },
    # ═══ Team 2: ml-pipeline ═══
    "ml_root": {
        "pid": 81000, "type": "claude-code", "project": "ml-pipeline",
        "depth": 0, "parent_agent_pid": None, "team_id": 81000,
        "log": DEMO_DIR / "ml_root.jsonl",
        "scenario": "ml_lead",
    },
    "ml_data": {
        "pid": 81100, "type": "claude-code", "project": "ml-pipeline",
        "depth": 1, "parent_agent_pid": 81000, "team_id": 81000,
        "log": DEMO_DIR / "ml_data.jsonl",
        "scenario": "data_prep",
    },
    "ml_model": {
        "pid": 81200, "type": "claude-code", "project": "ml-pipeline",
        "depth": 1, "parent_agent_pid": 81000, "team_id": 81000,
        "log": DEMO_DIR / "ml_model.jsonl",
        "scenario": "hyperparam_loop",
    },
    "ml_deploy": {
        "pid": 81300, "type": "claude-code", "project": "ml-pipeline",
        "depth": 1, "parent_agent_pid": 81000, "team_id": 81000,
        "log": DEMO_DIR / "ml_deploy.jsonl",
        "scenario": "deploy_spiral",
    },
}

for info in AGENTS.values():
    info["log"].touch()

# ── JSONL helpers ─────────────────────────────────────────────────────────

_CTR = 0

def _tid():
    global _CTR; _CTR += 1
    return f"toolu_{_CTR:08d}"

def _entry(role, tool=None, inp=None, text=None, tok_in=500, tok_out=200,
           cc=0, cr=100, err=False, sid="x", ts=None):
    ts = ts or datetime.utcnow()
    content = []
    if text:
        content.append({"type": "text", "text": text})
    if role == "assistant" and tool:
        content.append({"type": "tool_use", "id": _tid(), "name": tool, "input": inp or {}})
    elif role == "user" and tool:
        content.append({"type": "tool_result", "tool_use_id": _tid(),
                         "content": "Error: " + (text or "failed") if err else "OK",
                         "is_error": err})
    return {
        "type": role, "timestamp": ts.isoformat() + "Z",
        "message": {"role": role, "content": content,
                     "usage": {"input_tokens": tok_in, "output_tokens": tok_out,
                               "cache_creation_input_tokens": cc,
                               "cache_read_input_tokens": cr}},
        "sessionId": sid,
        "costUSD": round(tok_in * 3e-6 + tok_out * 15e-6, 6),
    }

def _w(path, e):
    with open(path, "a") as f:
        f.write(json.dumps(e) + "\n")

# ── Scenarios ─────────────────────────────────────────────────────────────

ECOM_FILES = ["src/App.tsx", "src/Cart.tsx", "src/Checkout.tsx", "src/ProductList.tsx",
              "api/routes.py", "api/models.py", "api/payments.py", "api/db.py",
              "tests/test_cart.py", "tests/test_checkout.py", "tests/test_api.py",
              "docker-compose.yml", "package.json"]

ML_FILES = ["data/clean.py", "data/loader.py", "models/train.py", "models/eval.py",
            "models/config.yaml", "deploy/Dockerfile", "deploy/k8s.yaml",
            "notebooks/eda.ipynb", "tests/test_model.py", "requirements.txt"]


def scenario_orchestrator(lp, sid):
    """Root: delegates, reads plans, runs integration tests. Healthy."""
    t = datetime.utcnow()
    turn = 0
    while True:
        turn += 1
        f = random.choice(ECOM_FILES)
        _w(lp, _entry("assistant", "Read", {"file_path": f},
            text=f"Reviewing {f} to check integration status with sub-agent work.",
            tok_in=900, tok_out=200, cr=400, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Read", ts=t, sid=sid))
        t += timedelta(seconds=1)

        if turn % 2 == 0:
            _w(lp, _entry("assistant", "Edit", {"file_path": f, "old_string": "v1", "new_string": "v2"},
                text=f"Updating {f} to integrate changes from sub-agents.",
                tok_in=700, tok_out=350, cr=300, ts=t, sid=sid))
            t += timedelta(seconds=3)
            _w(lp, _entry("user", "Edit", ts=t, sid=sid))
            t += timedelta(seconds=1)

        if turn % 4 == 0:
            _w(lp, _entry("assistant", "Bash", {"command": "npm run test:integration"},
                text="Running full integration suite.", tok_in=600, tok_out=100, ts=t, sid=sid))
            t += timedelta(seconds=5)
            _w(lp, _entry("user", "Bash", ts=t, sid=sid))
            t += timedelta(seconds=1)

        time.sleep(random.uniform(3, 5)); t = datetime.utcnow()


def scenario_frontend_dev(lp, sid):
    """Sub: builds React components. Mostly healthy, occasional hiccup."""
    t = datetime.utcnow()
    comps = ["Cart.tsx", "Checkout.tsx", "ProductList.tsx", "Header.tsx", "Footer.tsx"]
    turn = 0
    while True:
        turn += 1
        c = random.choice(comps)
        _w(lp, _entry("assistant", "Read", {"file_path": f"src/{c}"},
            text=f"Reading {c} component to add responsive styling.",
            tok_in=700, tok_out=120, cr=350, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Read", ts=t, sid=sid))
        t += timedelta(seconds=1)

        _w(lp, _entry("assistant", "Edit", {"file_path": f"src/{c}", "old_string": "className", "new_string": "className + responsive"},
            text=f"Adding responsive breakpoints to {c}.",
            tok_in=600, tok_out=280, cr=200, ts=t, sid=sid))
        t += timedelta(seconds=2)
        err = random.random() < 0.15  # 15% fail rate
        _w(lp, _entry("user", "Edit", err=err, ts=t, sid=sid))
        t += timedelta(seconds=1)

        if turn % 3 == 0:
            _w(lp, _entry("assistant", "Bash", {"command": "npm run lint && npm test"},
                text="Linting and testing components.", tok_in=500, tok_out=80, ts=t, sid=sid))
            t += timedelta(seconds=4)
            _w(lp, _entry("user", "Bash", ts=t, sid=sid))
            t += timedelta(seconds=1)

        time.sleep(random.uniform(3, 6)); t = datetime.utcnow()


def scenario_backend_errors(lp, sid):
    """Sub: writing API routes, DB connection keeps failing."""
    t = datetime.utcnow()
    err_count = 0
    while True:
        _w(lp, _entry("assistant", "Read", {"file_path": "api/db.py"},
            text="Checking the database connection pool configuration.",
            tok_in=800, tok_out=100, cr=50, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Read", ts=t, sid=sid))
        t += timedelta(seconds=1)

        _w(lp, _entry("assistant", "Edit", {"file_path": "api/routes.py", "old_string": "db.query", "new_string": "db.execute"},
            text="Switching from db.query to db.execute for better connection handling.",
            tok_in=700, tok_out=350, ts=t, sid=sid))
        t += timedelta(seconds=2)
        err = random.random() < 0.6  # 60% fail
        _w(lp, _entry("user", "Edit", err=err, ts=t, sid=sid))
        t += timedelta(seconds=1)

        # Always try the migration
        _w(lp, _entry("assistant", "Bash", {"command": "python api/db.py migrate"},
            text="Running DB migration to apply schema changes." if err_count < 5
                 else "I think maybe the issue is the migration. Let me try again...",
            tok_in=600, tok_out=200, ts=t, sid=sid))
        t += timedelta(seconds=3)
        bash_err = random.random() < 0.65
        _w(lp, _entry("user", "Bash", err=bash_err, text="Connection refused: postgres:5432", ts=t, sid=sid))
        if bash_err: err_count += 1
        t += timedelta(seconds=1)

        if err_count > 4:
            _w(lp, _entry("assistant", "Read", {"file_path": "docker-compose.yml"},
                text="Maybe the postgres container isn't running. Let me check docker-compose.",
                tok_in=500, tok_out=150, cr=30, ts=t, sid=sid))
            t += timedelta(seconds=2)
            _w(lp, _entry("user", "Read", ts=t, sid=sid))
            t += timedelta(seconds=1)

        time.sleep(random.uniform(2, 4)); t = datetime.utcnow()


def scenario_flaky_tests(lp, sid):
    """Sub: stuck re-running the same flaky test over and over."""
    t = datetime.utcnow()
    while True:
        # Read test file (same one every time)
        _w(lp, _entry("assistant", "Read", {"file_path": "tests/test_checkout.py"},
            text="Let me re-read the checkout test to understand why it's flaking.",
            tok_in=900, tok_out=80, cr=0, cc=400, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Read", ts=t, sid=sid))
        t += timedelta(seconds=1)

        # Same edit every cycle
        _w(lp, _entry("assistant", "Edit",
            {"file_path": "tests/test_checkout.py", "old_string": "assert total", "new_string": "assert round(total, 2)"},
            text="Adding rounding to fix floating point comparison.",
            tok_in=700, tok_out=200, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Edit", err=True, text="old_string not found in file", ts=t, sid=sid))
        t += timedelta(seconds=1)

        # Run test — always fails
        _w(lp, _entry("assistant", "Bash", {"command": "pytest tests/test_checkout.py -v"},
            text="Running the checkout test again.",
            tok_in=600, tok_out=150, ts=t, sid=sid))
        t += timedelta(seconds=4)
        _w(lp, _entry("user", "Bash", err=True, text="FAILED test_checkout_total - AssertionError", ts=t, sid=sid))
        t += timedelta(seconds=1)

        # Re-read (loop!)
        _w(lp, _entry("assistant", "Read", {"file_path": "tests/test_checkout.py"},
            text="Hmm, let me look at this test one more time.",
            tok_in=900, tok_out=80, cr=0, cc=400, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Read", ts=t, sid=sid))
        t += timedelta(seconds=1)

        time.sleep(random.uniform(2, 4)); t = datetime.utcnow()


def scenario_ml_lead(lp, sid):
    """Root: reading data, planning model architecture. Healthy."""
    t = datetime.utcnow()
    turn = 0
    while True:
        turn += 1
        f = random.choice(ML_FILES)
        _w(lp, _entry("assistant", "Read", {"file_path": f},
            text=f"Reviewing {f} to plan next training run.",
            tok_in=800, tok_out=180, cr=350, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Read", ts=t, sid=sid))
        t += timedelta(seconds=1)

        if turn % 2 == 0:
            edit_f = random.choice(["models/config.yaml", "models/train.py", "data/loader.py"])
            _w(lp, _entry("assistant", "Edit", {"file_path": edit_f, "old_string": "lr: 0.001", "new_string": "lr: 0.0005"},
                text=f"Tuning learning rate in {edit_f}.",
                tok_in=600, tok_out=250, cr=200, ts=t, sid=sid))
            t += timedelta(seconds=3)
            _w(lp, _entry("user", "Edit", ts=t, sid=sid))
            t += timedelta(seconds=1)

        if turn % 5 == 0:
            _w(lp, _entry("assistant", "Bash", {"command": "python models/eval.py --checkpoint latest"},
                text="Evaluating latest checkpoint metrics.",
                tok_in=500, tok_out=100, ts=t, sid=sid))
            t += timedelta(seconds=6)
            _w(lp, _entry("user", "Bash", ts=t, sid=sid))
            t += timedelta(seconds=1)

        time.sleep(random.uniform(3, 6)); t = datetime.utcnow()


def scenario_data_prep(lp, sid):
    """Sub: cleaning CSVs, occasional pandas errors."""
    t = datetime.utcnow()
    files = ["data/raw/users.csv", "data/raw/orders.csv", "data/raw/products.csv", "data/clean.py"]
    while True:
        f = random.choice(files)
        _w(lp, _entry("assistant", "Read", {"file_path": f},
            text=f"Reading {f} to check data quality.",
            tok_in=700, tok_out=130, cr=250, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Read", ts=t, sid=sid))
        t += timedelta(seconds=1)

        _w(lp, _entry("assistant", "Edit", {"file_path": "data/clean.py", "old_string": "dropna()", "new_string": "dropna(subset=['id'])"},
            text="Narrowing dropna to only required columns.",
            tok_in=600, tok_out=300, cr=150, ts=t, sid=sid))
        t += timedelta(seconds=2)
        err = random.random() < 0.3  # 30% fail
        _w(lp, _entry("user", "Edit", err=err, ts=t, sid=sid))
        t += timedelta(seconds=1)

        _w(lp, _entry("assistant", "Bash", {"command": "python data/clean.py --validate"},
            text="Running data validation pipeline.",
            tok_in=500, tok_out=100, ts=t, sid=sid))
        t += timedelta(seconds=3)
        _w(lp, _entry("user", "Bash", err=random.random() < 0.25, text="KeyError: 'user_id'", ts=t, sid=sid))
        t += timedelta(seconds=1)

        time.sleep(random.uniform(3, 5)); t = datetime.utcnow()


def scenario_hyperparam_loop(lp, sid):
    """Sub: stuck trying same hyperparameters, re-reading config."""
    t = datetime.utcnow()
    while True:
        _w(lp, _entry("assistant", "Read", {"file_path": "models/config.yaml"},
            text="Let me check the hyperparameter configuration again.",
            tok_in=800, tok_out=80, cr=0, cc=300, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Read", ts=t, sid=sid))
        t += timedelta(seconds=1)

        _w(lp, _entry("assistant", "Edit",
            {"file_path": "models/config.yaml", "old_string": "batch_size: 32", "new_string": "batch_size: 64"},
            text="Doubling batch size to see if training stabilizes.",
            tok_in=600, tok_out=180, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Edit", err=True, text="old_string not found", ts=t, sid=sid))
        t += timedelta(seconds=1)

        _w(lp, _entry("assistant", "Bash", {"command": "python models/train.py --epochs 1 --dry-run"},
            text="Trying a dry run with current config.",
            tok_in=700, tok_out=120, ts=t, sid=sid))
        t += timedelta(seconds=4)
        _w(lp, _entry("user", "Bash", err=True, text="OOM: CUDA out of memory", ts=t, sid=sid))
        t += timedelta(seconds=1)

        # Re-read same config (loop detector bait)
        _w(lp, _entry("assistant", "Read", {"file_path": "models/config.yaml"},
            text="Hmm, maybe I need to reduce the model size instead.",
            tok_in=800, tok_out=80, cr=0, cc=300, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Read", ts=t, sid=sid))
        t += timedelta(seconds=1)

        time.sleep(random.uniform(2, 4)); t = datetime.utcnow()


def scenario_deploy_spiral(lp, sid):
    """Sub: fighting Docker + k8s, everything fails, error spiral."""
    t = datetime.utcnow()
    cmds = [
        ("docker build -t ml-pipeline .", "ERROR: failed to solve: dockerfile parse error"),
        ("kubectl apply -f deploy/k8s.yaml", "error: unable to connect to server"),
        ("docker-compose up -d", "ERROR: Service 'model-server' failed to build"),
        ("kubectl rollout status deployment/ml-api", "error: deployment exceeded progress deadline"),
    ]
    idx = 0
    while True:
        cmd, errmsg = cmds[idx % len(cmds)]

        _w(lp, _entry("assistant", "Read", {"file_path": "deploy/Dockerfile" if "docker" in cmd else "deploy/k8s.yaml"},
            text=f"Checking deployment config before running: {cmd.split()[0]}",
            tok_in=700, tok_out=100, cr=40, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Read", ts=t, sid=sid))
        t += timedelta(seconds=1)

        _w(lp, _entry("assistant", "Edit",
            {"file_path": "deploy/Dockerfile", "old_string": "FROM python:3.11", "new_string": "FROM python:3.12"},
            text="Trying a newer base image to fix build.",
            tok_in=600, tok_out=250, ts=t, sid=sid))
        t += timedelta(seconds=2)
        _w(lp, _entry("user", "Edit", err=random.random() < 0.5, ts=t, sid=sid))
        t += timedelta(seconds=1)

        _w(lp, _entry("assistant", "Bash", {"command": cmd},
            text=f"Running deployment: {cmd}",
            tok_in=500, tok_out=180, ts=t, sid=sid))
        t += timedelta(seconds=4)
        _w(lp, _entry("user", "Bash", err=True, text=errmsg, ts=t, sid=sid))
        t += timedelta(seconds=1)

        idx += 1
        time.sleep(random.uniform(2, 4)); t = datetime.utcnow()


SCENARIOS = {
    "orchestrator": scenario_orchestrator,
    "frontend_dev": scenario_frontend_dev,
    "backend_errors": scenario_backend_errors,
    "flaky_tests": scenario_flaky_tests,
    "ml_lead": scenario_ml_lead,
    "data_prep": scenario_data_prep,
    "hyperparam_loop": scenario_hyperparam_loop,
    "deploy_spiral": scenario_deploy_spiral,
}

# ── Main ──────────────────────────────────────────────────────────────────

def main():
    from agentwatch.discovery import AgentProcess, _compute_depths, _assign_team_ids, build_teams
    from agentwatch.ui.multi_app import MultiAgentWatchApp

    processes = []
    for name, info in AGENTS.items():
        processes.append(AgentProcess(
            pid=info["pid"], agent_type=info["type"],
            working_directory=Path(f"/projects/{info['project']}"),
            log_file=info["log"], session_id=f"demo-{name}",
            cpu_percent=random.uniform(5, 45), memory_mb=random.uniform(80, 600),
            uptime="00:08:00", command=f"claude --project {info['project']}",
            parent_pid=info["parent_agent_pid"],
            parent_agent_pid=info["parent_agent_pid"],
            depth=info["depth"], team_id=info["team_id"],
        ))

    _compute_depths(processes)
    _assign_team_ids(processes)

    teams = build_teams(processes)
    print(f"\n{'='*60}")
    print(f"  AgentWatch Team Demo — {len(processes)} agents, {len(teams)} teams")
    print(f"{'='*60}\n")
    for team in teams:
        print(f"  TEAM {team.name} ({team.member_count} members, {team.subagent_count} sub-agents)")
        for m in team.members:
            role = "root" if m.is_root else f"  sub(L{m.depth})"
            key = [k for k, v in AGENTS.items() if v["pid"] == m.pid][0]
            print(f"    [{role}] PID {m.pid} — {AGENTS[key]['scenario']}")
    print()

    # Seed each log with initial entries
    for name, info in AGENTS.items():
        t0 = datetime.utcnow() - timedelta(minutes=8)
        src_files = ECOM_FILES if "ecom" in name else ML_FILES
        for i in range(8):
            f = random.choice(src_files)
            _w(info["log"], _entry("assistant", "Read", {"file_path": f},
                text=f"Initial exploration: reading {f}.",
                tok_in=500, tok_out=100, cr=200,
                ts=t0 + timedelta(seconds=i * 20), sid=f"demo-{name}"))
            _w(info["log"], _entry("user", "Read",
                ts=t0 + timedelta(seconds=i * 20 + 2), sid=f"demo-{name}"))

    # Start scenario threads
    for name, info in AGENTS.items():
        fn = SCENARIOS[info["scenario"]]
        threading.Thread(target=fn, args=(info["log"], f"demo-{name}"), daemon=True).start()
        print(f"  Started '{info['scenario']}' for {name}")

    print(f"\n  Launching TUI... press 'q' to quit")
    print(f"  Use ↑/↓ to browse agents & teams\n")

    class DemoApp(MultiAgentWatchApp):
        def _refresh_processes(self):
            pass  # fake PIDs — skip real ps scan

    app = DemoApp(agent_processes=processes, security_mode=False)
    app.run()

    shutil.rmtree(DEMO_DIR, ignore_errors=True)
    print("Demo cleaned up.")


if __name__ == "__main__":
    main()
