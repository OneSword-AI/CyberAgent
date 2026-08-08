"""黑板驱动自治 Agent MVP — 入口。

用法:
    python main.py                   # 运行内置演示场景
    python main.py --reset           # 清空黑板后重新运行
    python main.py --input "..."     # 自定义输入信号
"""
from __future__ import annotations
import argparse
import json
import logging
import sys
from pathlib import Path

# Ensure package root is importable
sys.path.insert(0, str(Path(__file__).parent))

from runtime import Runtime

DATA_DIR       = Path("data")
BB_PATH        = DATA_DIR / "blackboard.json"
CHECKPOINT_PATH = DATA_DIR / "checkpoint.json"
MEMORY_PATH    = DATA_DIR / "memory.json"
CONFIG_PATH    = Path("config/agents.yaml")

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(name)s: %(message)s",
)


def seed_memory() -> None:
    """Seed an initial memory store for the MemoryAgent to recall from."""
    if MEMORY_PATH.exists():
        return
    MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    entries = [
        {
            "label":       "port_scan",
            "subject":     "192.168.1.1",
            "tags":        ["port_activity", "scan"],
            "description": "Previously observed port scanning from this host",
        },
        {
            "label":       "brute_force_attempt",
            "subject":     "10.0.0.5",
            "tags":        ["auth_activity", "failure"],
            "description": "Repeated SSH login failures in prior incident",
        },
    ]
    MEMORY_PATH.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    print(f"[Setup] Memory seeded at {MEMORY_PATH}")


def reset() -> None:
    for p in [BB_PATH, CHECKPOINT_PATH]:
        if p.exists():
            p.unlink()
            print(f"[Setup] Removed {p}")


def demo_inputs() -> list[str]:
    return [
        "Detected repeated port scan from 192.168.1.1 on port 22, 80, 443",
        "Multiple failed login attempts on 10.0.0.5 — possible brute force",
        "SQL error in web log: SELECT * FROM users WHERE id=1 OR 1=1",
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true", help="Clear blackboard before running")
    parser.add_argument("--input", metavar="TEXT", help="Custom raw input signal")
    args = parser.parse_args()

    if args.reset:
        reset()

    seed_memory()

    rt = Runtime(
        config_path=CONFIG_PATH,
        blackboard_path=BB_PATH,
        checkpoint_path=CHECKPOINT_PATH,
        max_rounds=15,
        quiesce_rounds=2,
    )

    inputs = [args.input] if args.input else demo_inputs()
    print(f"\n[Setup] Posting {len(inputs)} raw input signal(s) to blackboard:")
    for text in inputs:
        sid = rt.post_input(text)
        print(f"  → {text[:70]!r} [{sid[:8]}]")

    print("\n[Runtime] Starting agent loop …")
    rt.run()


if __name__ == "__main__":
    main()
