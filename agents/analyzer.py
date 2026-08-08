"""分析 Agent — 从 OBSERVATION/EVIDENCE 生成 HYPOTHESIS 和 CANDIDATE_CONCLUSION。"""
from __future__ import annotations
from blackboard import SType, Signal
from agents.base import AgentBase

# tag-set → hypothesis label
_RULES: list[tuple[set[str], str, float]] = [
    ({"port_activity", "scan"},       "port_scan",             0.65),
    ({"auth_activity", "failure"},    "brute_force_attempt",   0.70),
    ({"exploit_attempt"},             "active_exploitation",   0.60),
    ({"brute_force"},                 "brute_force_attempt",   0.75),
    ({"sql_injection"},               "sql_injection_attempt", 0.80),
    ({"xss"},                         "xss_attempt",           0.75),
    ({"error"},                       "service_error",         0.50),
    ({"generic"},                     "unknown_activity",      0.30),
]


class AnalyzerAgent(AgentBase):
    subscribes_to = [SType.OBSERVATION, SType.EVIDENCE]

    def _handle(self, signal: Signal, round_num: int) -> None:
        if signal.type == SType.OBSERVATION:
            self._analyze_observation(signal, round_num)
        else:
            self._analyze_evidence(signal, round_num)

    def _analyze_observation(self, signal: Signal, round_num: int) -> None:
        tags = set(signal.payload.get("tags", []))
        subject = signal.payload.get("subject", "unknown")

        for rule_tags, hypothesis, confidence in _RULES:
            if rule_tags & tags:  # overlap sufficient
                payload = {
                    "subject":    subject,
                    "hypothesis": hypothesis,
                    "confidence": confidence,
                    "basis_tags": list(rule_tags & tags),
                }
                self.post(SType.HYPOTHESIS, payload, parent=signal, round_num=round_num)
                print(f"  [Analyzer] HYPOTHESIS: {hypothesis!r} "
                      f"(confidence={confidence}, subject={subject!r})")
                break  # one hypothesis per observation for MVP

    def _analyze_evidence(self, signal: Signal, round_num: int) -> None:
        subject    = signal.payload.get("subject", "unknown")
        hyp_label  = signal.payload.get("supports_hypothesis", "")
        confidence = signal.payload.get("confidence", 0.6)

        if not hyp_label:
            return

        # Escalate to candidate conclusion when evidence looks strong
        if confidence >= 0.6:
            payload = {
                "subject":    subject,
                "conclusion": hyp_label,
                "confidence": min(confidence + 0.1, 0.95),
                "source":     "evidence_escalation",
            }
            self.post(SType.CANDIDATE_CONCLUSION, payload,
                      parent=signal, round_num=round_num)
            print(f"  [Analyzer] CANDIDATE_CONCLUSION: {hyp_label!r} "
                  f"(confidence={payload['confidence']:.2f})")
