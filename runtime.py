"""运行时 — 加载 YAML Agent 定义，驱动多轮黑板分发，每轮写检查点。"""
from __future__ import annotations
import json
import logging
import time
from pathlib import Path
from typing import Any

import yaml

from blackboard import Blackboard, Signal, SType
from agents.base import AgentBase
from agents.observer import ObserverAgent
from agents.analyzer import AnalyzerAgent
from agents.questioner import QuestionerAgent
from agents.memory_agent import MemoryAgent

logger = logging.getLogger(__name__)

_AGENT_REGISTRY: dict[str, type[AgentBase]] = {
    "observer":  ObserverAgent,
    "analyzer":  AnalyzerAgent,
    "questioner": QuestionerAgent,
    "memory":    MemoryAgent,
}


class Runtime:
    def __init__(
        self,
        config_path: Path,
        blackboard_path: Path,
        checkpoint_path: Path,
        max_rounds: int = 20,
        quiesce_rounds: int = 2,
    ) -> None:
        self.blackboard      = Blackboard(blackboard_path)
        self.checkpoint_path = checkpoint_path
        self.max_rounds      = max_rounds
        self.quiesce_rounds  = quiesce_rounds
        self.agents: list[AgentBase] = self._load_agents(config_path)
        self.round_num       = self._restore_checkpoint()

    # ── agent loading ─────────────────────────────────────────────────────────

    def _load_agents(self, config_path: Path) -> list[AgentBase]:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        agents: list[AgentBase] = []
        for spec in raw.get("agents", []):
            agent_type = spec["type"]
            cls = _AGENT_REGISTRY.get(agent_type)
            if cls is None:
                raise ValueError(f"Unknown agent type: {agent_type!r}")
            agents.append(cls(
                agent_id=spec["id"],
                config=spec.get("config", {}),
                blackboard=self.blackboard,
            ))
            logger.info("Loaded agent: %s (%s)", spec["id"], agent_type)
        return agents

    # ── checkpoint ────────────────────────────────────────────────────────────

    def _restore_checkpoint(self) -> int:
        if self.checkpoint_path.exists():
            data = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            round_num = data.get("round_num", 0)
            logger.info("Restored from checkpoint: round %d", round_num)
            print(f"[Runtime] Restored from checkpoint at round {round_num}")
            return round_num
        return 0

    def _save_checkpoint(self, round_num: int, signal_count: int) -> None:
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "round_num":    round_num,
            "signal_count": signal_count,
            "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "summary":      self.blackboard.summary(),
        }
        self.checkpoint_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # ── main loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        idle_rounds = 0
        while self.round_num < self.max_rounds:
            self.round_num += 1
            print(f"\n{'─' * 50}")
            print(f"[Runtime] Round {self.round_num}")

            total_handled = 0
            for agent in self.agents:
                handled = agent.run_once(self.round_num)
                total_handled += handled

            self._save_checkpoint(self.round_num, len(self.blackboard.signals))
            print(f"[Runtime] Round {self.round_num} complete — "
                  f"signals handled: {total_handled}, "
                  f"blackboard size: {len(self.blackboard.signals)}")

            if total_handled == 0:
                idle_rounds += 1
                if idle_rounds >= self.quiesce_rounds:
                    print(f"[Runtime] Quiesced after {idle_rounds} idle rounds.")
                    break
            else:
                idle_rounds = 0

        self._print_summary()

    def _print_summary(self) -> None:
        print(f"\n{'═' * 50}")
        print("[Runtime] Final blackboard summary:")
        for sig_type, count in sorted(self.blackboard.summary().items()):
            print(f"  {sig_type:<28} {count}")
        conclusions = self.blackboard.conclusions()
        if conclusions:
            print("\n[Runtime] Confirmed conclusions:")
            for c in conclusions:
                p = c.payload
                print(f"  • {p.get('conclusion')!r}  subject={p.get('subject')!r} "
                      f"confidence={p.get('confidence'):.2f}  "
                      f"evidence={p.get('evidence_count')}")
        else:
            print("\n[Runtime] No conclusions reached.")

    def post_input(self, text: str) -> str:
        sig = Signal(type=SType.RAW_INPUT, source="user", payload={"text": text})
        return self.blackboard.post(sig)
