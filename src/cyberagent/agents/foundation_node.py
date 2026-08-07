from cyberagent.agents.foundation import AnalystAgent, CriticAgent, MemoryAgent, ObserverAgent
from cyberagent.evidence import add_finding
from cyberagent.models import ChallengeState
from cyberagent.signals import Signal, make_signal
from cyberagent.trace import add_trace_event


def run_foundation_agents(state: ChallengeState) -> ChallengeState:
    """Run foundational signal agents against the current challenge input."""
    input_signal = make_signal(
        type="challenge_input",
        challenge_id=state.get("challenge_id", ""),
        source="foundation_node",
        payload={
            "title": state.get("title", ""),
            "description": state.get("description", ""),
            "attachments": state.get("attachments", []),
            "remote_targets": state.get("remote_targets", []),
        },
        provenance="input",
    )
    observation = ObserverAgent().process(input_signal)[0]
    memory_prior = MemoryAgent().process(input_signal)[0]
    hypothesis = AnalystAgent().process(observation)[0]
    critic_report = CriticAgent().process(hypothesis)[0]
    produced: list[Signal] = [
        input_signal,
        observation,
        memory_prior,
        hypothesis,
        critic_report,
    ]

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
