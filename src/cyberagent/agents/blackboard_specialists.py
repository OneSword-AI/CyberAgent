from dataclasses import dataclass

from cyberagent.agents.registry import SPECIALIST_AGENTS
from cyberagent.agents.specialist_signals import make_specialist_result_signal
from cyberagent.agents.specialists import apply_specialist_result
from cyberagent.blackboard import Blackboard
from cyberagent.evidence import add_finding
from cyberagent.models import ChallengeState, SpecialistResult
from cyberagent.signals import Signal
from cyberagent.trace import add_trace_event


@dataclass(frozen=True)
class BlackboardSpecialistAgent:
    """Autonomous wrapper for a specialist that consumes blackboard tasks."""

    name: str
    subscriptions: set[str]

    def can_process(self, signal: Signal) -> bool:
        return signal["type"] in self.subscriptions

    def process(self, state: ChallengeState) -> SpecialistResult:
        return SPECIALIST_AGENTS[self.name]({**state, "active_agents": [self.name]})


BLACKBOARD_SPECIALISTS = {
    name: BlackboardSpecialistAgent(name=name, subscriptions={"feedback"})
    for name in SPECIALIST_AGENTS
}


def run_blackboard_specialists(state: ChallengeState) -> ChallengeState:
    """Let specialist Agents claim matching blackboard tasks and process them."""
    challenge_id = state.get("challenge_id", "")
    board = Blackboard(state.get("signals", []))
    next_state = state
    claimed_agents: list[str] = []
    processed = 0

    for agent in BLACKBOARD_SPECIALISTS.values():
        for signal in board.query(
            challenge_id=challenge_id,
            types=agent.subscriptions,
            status="pending",
            recipient=agent.name,
        ):
            if not agent.can_process(signal):
                continue
            if not board.claim(signal_id=signal["id"], agent=agent.name):
                continue

            try:
                result = agent.process(next_state)
            except Exception:
                board.mark_failed(signal["id"])
                raise

            next_state = apply_specialist_result(next_state, result)
            board.post(
                make_specialist_result_signal(
                    next_state,
                    result,
                    parent_ids=[signal["id"]],
                )
            )
            board.mark_completed(signal["id"])
            claimed_agents.append(agent.name)
            processed += 1

    next_state = {
        **next_state,
        "signals": board.snapshot(),
        "active_agents": list(dict.fromkeys(claimed_agents)),
        "published_specialist_results": len(next_state.get("specialist_results", [])),
    }
    next_state = add_trace_event(
        next_state,
        node="blackboard_specialists",
        event="blackboard.dispatch",
        details={"processed": processed, "active_agents": next_state["active_agents"]},
    )
    return add_finding(
        next_state,
        agent="blackboard_specialists",
        summary=f"Processed {processed} blackboard specialist task(s).",
        evidence={"active_agents": next_state["active_agents"]},
    )
