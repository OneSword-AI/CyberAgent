from cyberagent.agents.constants import CATEGORY_TO_AGENT, KNOWN_AGENT_NAMES
from cyberagent.evidence import add_finding
from cyberagent.models import ChallengeState
from cyberagent.trace import add_trace_event


def route_agent(state: ChallengeState) -> ChallengeState:
    """Select the specialist agents that should handle the challenge next."""
    active_agents = _select_agents(state)

    next_state: ChallengeState = {
            **state,
            "active_agents": active_agents,
    }
    next_state = add_trace_event(
        next_state,
        node="route_agent",
        event="agent.route",
        details={"active_agents": active_agents},
    )
    return add_finding(
        next_state,
        agent="route_agent",
        summary=f"Scheduled agents: {', '.join(active_agents)}",
        evidence={
            "predicted_categories": state.get("predicted_categories", []),
            "next_agents": state.get("next_agents", []),
            "active_agents": active_agents,
        },
    )


def _select_agents(state: ChallengeState) -> list[str]:
    agents = _valid_agent_names(state.get("next_agents", []))
    if agents:
        return agents

    categories = state.get("predicted_categories", [])
    agents = [CATEGORY_TO_AGENT.get(category, "other_agent") for category in categories]
    agents = _valid_agent_names(agents)
    return agents or ["other_agent"]


def _valid_agent_names(values: list[str]) -> list[str]:
    known_agent_names = set(KNOWN_AGENT_NAMES)
    agents: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        value = value.strip()
        if value in known_agent_names:
            agents.append(value)

    return list(dict.fromkeys(agents))
