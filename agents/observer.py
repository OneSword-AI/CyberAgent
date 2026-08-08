"""观察 Agent — 将 RAW_INPUT 规范化为结构化 OBSERVATION。"""
from __future__ import annotations
import re
from blackboard import SType, Signal
from agents.base import AgentBase


class ObserverAgent(AgentBase):
    subscribes_to = [SType.RAW_INPUT]

    def _handle(self, signal: Signal, round_num: int) -> None:
        raw: str = signal.payload.get("text", "")
        observation = {
            "subject":     self._extract_subject(raw),
            "raw_text":    raw,
            "tags":        self._extract_tags(raw),
            "confidence":  0.7,
        }
        self.post(SType.OBSERVATION, observation, parent=signal, round_num=round_num)
        print(f"  [Observer] OBSERVATION posted: subject={observation['subject']!r}, "
              f"tags={observation['tags']}")

    # ── private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_subject(text: str) -> str:
        # Extract first IP/host-like token, else first noun phrase
        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
        if ip_match:
            return ip_match.group(1)
        host_match = re.search(r"\b([a-zA-Z0-9_-]+\.[a-zA-Z]{2,})\b", text)
        if host_match:
            return host_match.group(1)
        # Fallback: first non-stopword token
        tokens = [t for t in text.split() if len(t) > 3]
        return tokens[0].lower() if tokens else "unknown"

    @staticmethod
    def _extract_tags(text: str) -> list[str]:
        tags = []
        lower = text.lower()
        keywords = {
            "port": "port_activity",
            "scan": "scan",
            "login": "auth_activity",
            "fail": "failure",
            "error": "error",
            "exploit": "exploit_attempt",
            "brute": "brute_force",
            "sql": "sql_injection",
            "xss": "xss",
        }
        for kw, tag in keywords.items():
            if kw in lower:
                tags.append(tag)
        return tags or ["generic"]
