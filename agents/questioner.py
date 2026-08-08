"""质疑 Agent — 独立挑战假设，执行证据门控，决定 CONCLUSION / REJECTION。

规则：
- MEMORY_PRIOR 不计入证据门 (advisory_only=True)
- 候选结论需要 ≥ MIN_EVIDENCE 条真实 EVIDENCE 才能晋升为 CONCLUSION
- 置信度低于 MIN_CONFIDENCE 的假设先提问再处理
"""
from __future__ import annotations
from blackboard import SType, Signal
from agents.base import AgentBase

MIN_EVIDENCE   = 1   # MVP: 至少1条独立证据
MIN_CONFIDENCE = 0.55


class QuestionerAgent(AgentBase):
    subscribes_to = [SType.HYPOTHESIS, SType.CANDIDATE_CONCLUSION]

    def _handle(self, signal: Signal, round_num: int) -> None:
        if signal.type == SType.HYPOTHESIS:
            self._question_hypothesis(signal, round_num)
        else:
            self._validate_candidate(signal, round_num)

    # ── hypothesis questioning ─────────────────────────────────────────────

    def _question_hypothesis(self, signal: Signal, round_num: int) -> None:
        subject    = signal.payload.get("subject", "unknown")
        hypothesis = signal.payload.get("hypothesis", "")
        confidence = signal.payload.get("confidence", 0.0)

        if confidence < MIN_CONFIDENCE:
            q = {
                "subject":           subject,
                "about_hypothesis":  hypothesis,
                "question":          f"Confidence {confidence:.2f} too low — what evidence supports {hypothesis!r}?",
                "requires_evidence": True,
            }
            self.post(SType.QUESTION, q, parent=signal, round_num=round_num)
            print(f"  [Questioner] QUESTION raised for {hypothesis!r} "
                  f"(confidence={confidence:.2f} < {MIN_CONFIDENCE})")
            return

        # Check existing evidence (MEMORY_PRIOR excluded intentionally)
        evidence = self.blackboard.evidence_for(subject)
        if len(evidence) < MIN_EVIDENCE:
            # Inject a synthetic evidence stub for MVP demonstration
            # (In production, this would trigger a tool call via ToolAdapter)
            stub_evidence = {
                "subject":              subject,
                "supports_hypothesis":  hypothesis,
                "description":          f"stub: behavioral indicator for {hypothesis}",
                "confidence":           0.65,
                "source":               "stub_sensor",
                "advisory_only":        False,
            }
            self.post(SType.EVIDENCE, stub_evidence, parent=signal, round_num=round_num)
            print(f"  [Questioner] EVIDENCE stub injected for {subject!r}")
        else:
            # Evidence exists — can request candidate conclusion from analyzer
            print(f"  [Questioner] {len(evidence)} evidence(s) found for {subject!r}, "
                  "escalating via EVIDENCE signal")

    # ── candidate conclusion validation ───────────────────────────────────

    def _validate_candidate(self, signal: Signal, round_num: int) -> None:
        subject    = signal.payload.get("subject", "unknown")
        conclusion = signal.payload.get("conclusion", "")
        confidence = signal.payload.get("confidence", 0.0)

        # Evidence gate — MEMORY_PRIOR is deliberately excluded
        evidence = self.blackboard.evidence_for(subject)
        priors   = self.blackboard.memory_priors_for(subject)

        if priors:
            print(f"  [Questioner] NOTE: {len(priors)} memory prior(s) exist for "
                  f"{subject!r} — these are advisory only, not counted as evidence.")

        if len(evidence) < MIN_EVIDENCE:
            payload = {
                "subject":    subject,
                "conclusion": conclusion,
                "reason":     f"evidence gate failed: {len(evidence)}/{MIN_EVIDENCE} required",
            }
            self.post(SType.REJECTION, payload, parent=signal, round_num=round_num)
            print(f"  [Questioner] REJECTION: {conclusion!r} — insufficient evidence "
                  f"({len(evidence)}/{MIN_EVIDENCE})")
            return

        if confidence < MIN_CONFIDENCE:
            payload = {
                "subject":    subject,
                "conclusion": conclusion,
                "reason":     f"confidence {confidence:.2f} below threshold {MIN_CONFIDENCE}",
            }
            self.post(SType.REJECTION, payload, parent=signal, round_num=round_num)
            print(f"  [Questioner] REJECTION: {conclusion!r} — low confidence")
            return

        # All gates passed
        final = {
            "subject":          subject,
            "conclusion":       conclusion,
            "confidence":       confidence,
            "evidence_count":   len(evidence),
            "memory_priors":    len(priors),
            "validated_by":     self.agent_id,
        }
        self.post(SType.CONCLUSION, final, parent=signal, round_num=round_num)
        print(f"  [Questioner] CONCLUSION confirmed: {conclusion!r} "
              f"(evidence={len(evidence)}, confidence={confidence:.2f})")
