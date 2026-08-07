from cyberagent.models import ChallengeState


CATEGORY_TO_AGENT = {
    "Web": "web_agent",
    "Pwn": "pwn_agent",
    "Reverse": "reverse_agent",
    "Crypto": "crypto_agent",
    "Misc": "misc_agent",
    "Forensics": "forensics_agent",
    "Other": "other_agent",
}
KNOWN_AGENT_NAMES = set(CATEGORY_TO_AGENT.values())


def route_agent(state: ChallengeState) -> ChallengeState:
    """Select the specialist agents that should handle the challenge next."""
    active_agents = _select_agents(state)

    finding = {
        "agent": "route_agent",
        "summary": f"Scheduled agents: {', '.join(active_agents)}",
        "evidence": {
            "predicted_categories": state.get("predicted_categories", []),
            "next_agents": state.get("next_agents", []),
            "active_agents": active_agents,
        },
    }

    return {
        **state,
        "active_agents": active_agents,
        "findings": [*state.get("findings", []), finding],
    }


def _select_agents(state: ChallengeState) -> list[str]:
    agents = _valid_agent_names(state.get("next_agents", []))
    if agents:
        return agents

    categories = state.get("predicted_categories", [])
    agents = [CATEGORY_TO_AGENT.get(category, "other_agent") for category in categories]
    agents = _valid_agent_names(agents)
    return agents or ["other_agent"]


def _valid_agent_names(values: list[str]) -> list[str]:
    agents: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        value = value.strip()
        if value in KNOWN_AGENT_NAMES:
            agents.append(value)

    return list(dict.fromkeys(agents))
