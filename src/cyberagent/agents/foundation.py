from cyberagent.blackboard import Blackboard
from cyberagent.signals import Signal, is_visible_to, make_signal


class SignalAgent:
    name = "signal_agent"
    subscriptions: set[str] = set()

    def can_process(self, signal: Signal) -> bool:
        return signal["type"] in self.subscriptions

    def process_pending(self, blackboard: Blackboard, *, challenge_id: str) -> list[Signal]:
        produced: list[Signal] = []
        for signal in blackboard.query(
            challenge_id=challenge_id,
            status="pending",
            recipient=self.name,
        ):
            if not is_visible_to(signal, self.name) or not self.can_process(signal):
                continue
            if not blackboard.claim(signal_id=signal["id"], agent=self.name):
                continue
            try:
                produced.extend(self.process(signal))
            except Exception:
                blackboard.mark_failed(signal["id"])
                raise
            blackboard.mark_completed(signal["id"])
        for signal in produced:
            blackboard.post(signal)
        return produced

    def process(self, signal: Signal) -> list[Signal]:
        return []


class ObserverAgent(SignalAgent):
    name = "observer"
    subscriptions = {"challenge_input"}

    def process(self, signal: Signal) -> list[Signal]:
        return [
            make_signal(
                type="observation",
                challenge_id=signal["challenge_id"],
                source=self.name,
                payload={"summary": "challenge observed", "input": signal["payload"]},
                provenance="inference",
                parent_ids=[signal["id"]],
            )
        ]


class AnalystAgent(SignalAgent):
    name = "analyst"
    subscriptions = {"observation"}

    def process(self, signal: Signal) -> list[Signal]:
        return [
            make_signal(
                type="hypothesis",
                challenge_id=signal["challenge_id"],
                source=self.name,
                payload={"summary": "candidate solving direction", "basis": signal["payload"]},
                provenance="inference",
                parent_ids=[signal["id"]],
            )
        ]


class CriticAgent(SignalAgent):
    name = "critic"
    subscriptions = {"hypothesis"}

    def process(self, signal: Signal) -> list[Signal]:
        return [
            make_signal(
                type="critic_report",
                challenge_id=signal["challenge_id"],
                source=self.name,
                payload={"verdict": "approved", "basis": "hypothesis is structurally valid"},
                provenance="critic",
                parent_ids=[signal["id"]],
            )
        ]


class MemoryAgent(SignalAgent):
    name = "memory"
    subscriptions = {"challenge_input", "observation"}

    def process(self, signal: Signal) -> list[Signal]:
        return [
            make_signal(
                type="memory_prior",
                challenge_id=signal["challenge_id"],
                source=self.name,
                payload={"summary": "similar past pattern may apply"},
                provenance="memory_prior",
                parent_ids=[signal["id"]],
            )
        ]
