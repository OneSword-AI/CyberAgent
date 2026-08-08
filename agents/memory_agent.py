"""记忆 Agent — 仅提供先验，严禁直接确认结论。

所有输出的 payload 均包含 advisory_only=True，
Questioner 证据门控中会主动排除 MEMORY_PRIOR 类型。
"""
from __future__ import annotations
import json
from pathlib import Path
from blackboard import SType, Signal
from agents.base import AgentBase


class MemoryAgent(AgentBase):
    subscribes_to = [SType.OBSERVATION, SType.HYPOTHESIS]

    def __init__(self, agent_id, config, blackboard):
        super().__init__(agent_id, config, blackboard)
        self.memory_path = Path(config.get("memory_path", "data/memory.json"))
        self._memory: list[dict] = self._load_memory()

    # ── memory I/O ────────────────────────────────────────────────────────────

    def _load_memory(self) -> list[dict]:
        if self.memory_path.exists():
            return json.loads(self.memory_path.read_text(encoding="utf-8"))
        return []

    def save_memory(self, entry: dict) -> None:
        self._memory.append(entry)
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)
        self.memory_path.write_text(
            json.dumps(self._memory, indent=2), encoding="utf-8"
        )

    # ── signal handling ───────────────────────────────────────────────────────

    def _handle(self, signal: Signal, round_num: int) -> None:
        if signal.type == SType.OBSERVATION:
            self._recall_for_observation(signal, round_num)
        else:
            self._recall_for_hypothesis(signal, round_num)

    def _recall_for_observation(self, signal: Signal, round_num: int) -> None:
        subject = signal.payload.get("subject", "unknown")
        tags    = set(signal.payload.get("tags", []))
        matches = [m for m in self._memory if self._matches(m, subject, tags)]

        for match in matches[:2]:  # cap to 2 priors per observation
            prior = {
                "subject":      subject,
                "prior_label":  match.get("label", "unknown"),
                "description":  match.get("description", ""),
                "source":       "memory",
                # CRITICAL: must not be used to confirm conclusions
                "advisory_only": True,
                "note":         "Prior knowledge only. Cannot substitute for evidence.",
            }
            self.post(SType.MEMORY_PRIOR, prior, parent=signal, round_num=round_num)
            print(f"  [Memory] MEMORY_PRIOR for {subject!r}: "
                  f"{match.get('label')!r} (advisory only)")

    def _recall_for_hypothesis(self, signal: Signal, round_num: int) -> None:
        subject    = signal.payload.get("subject", "unknown")
        hypothesis = signal.payload.get("hypothesis", "")
        # Check if memory has past conclusions about this hypothesis type
        past = [m for m in self._memory if m.get("label") == hypothesis]
        if past:
            prior = {
                "subject":       subject,
                "prior_label":   hypothesis,
                "past_count":    len(past),
                "description":   f"Seen {len(past)} time(s) historically",
                "advisory_only": True,
                "note":          "Historical frequency is not evidence of current occurrence.",
            }
            self.post(SType.MEMORY_PRIOR, prior, parent=signal, round_num=round_num)
            print(f"  [Memory] MEMORY_PRIOR: {hypothesis!r} seen {len(past)}x in history "
                  "(advisory only)")

    @staticmethod
    def _matches(entry: dict, subject: str, tags: set[str]) -> bool:
        if entry.get("subject") == subject:
            return True
        entry_tags = set(entry.get("tags", []))
        return bool(entry_tags & tags)
