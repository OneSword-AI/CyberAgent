from cyberagent.agents.foundation import AnalystAgent, CriticAgent, MemoryAgent, ObserverAgent
from cyberagent.blackboard import Blackboard
from cyberagent.evidence import add_finding
from cyberagent.models import ChallengeState
from cyberagent.signals import Signal, make_signal
from cyberagent.trace import add_trace_event


def run_foundation_agents(state: ChallengeState) -> ChallengeState:
    """Run foundational signal agents through a shared blackboard message chain."""
    challenge_id = state.get("challenge_id", "")
    blackboard = Blackboard()
    input_signal = make_signal(
        type="challenge_input",
        challenge_id=challenge_id,
        source="foundation_node",
        payload={
            "title": state.get("title", ""),
            "description": state.get("description", ""),
            "attachments": state.get("attachments", []),
            "remote_targets": state.get("remote_targets", []),
        },
        provenance="input",
        recipients=["observer", "memory"],
    )
    blackboard.post(input_signal)

    observer = ObserverAgent()
    memory = MemoryAgent()
    analyst = AnalystAgent()
    critic = CriticAgent()
    observer.process_pending(blackboard, challenge_id=challenge_id)
    memory.process_pending(blackboard, challenge_id=challenge_id)
    analyst.process_pending(blackboard, challenge_id=challenge_id)
    critic.process_pending(blackboard, challenge_id=challenge_id)

    produced: list[Signal] = blackboard.query(challenge_id=challenge_id)
    next_state: ChallengeState = {
        **state,
        "signals": [*state.get("signals", []), *produced],
    }
    next_state = add_trace_event(
        next_state,
        node="foundation_agents",
        event="foundation.run",
        details={"signals": len(produced)},
    )
    return add_finding(
        next_state,
        agent="foundation_agents",
        summary=f"Produced {len(produced)} structured signal(s).",
        evidence={"signal_types": [signal["type"] for signal in produced]},
    )
