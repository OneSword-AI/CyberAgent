from cyberagent.agents.router import route_agent
from cyberagent.graph import initial_state


def test_route_agent_uses_next_agents():
    state = initial_state("1")
    state.update(
        {
            "predicted_categories": ["Web"],
            "next_agents": ["web_agent", "crypto_agent", "web_agent"],
        }
    )

    result = route_agent(state)

    assert result["active_agents"] == ["web_agent", "crypto_agent"]
    assert result["findings"][-1]["agent"] == "route_agent"


def test_route_agent_derives_agents_from_categories_when_next_agents_empty():
    state = initial_state("1")
    state.update(
        {
            "predicted_categories": ["Reverse", "Pwn"],
            "next_agents": [],
        }
    )

    result = route_agent(state)

    assert result["active_agents"] == ["reverse_agent", "pwn_agent"]


def test_route_agent_falls_back_to_other_agent():
    state = initial_state("1")
    state.update(
        {
            "predicted_categories": [],
            "next_agents": ["unknown_agent"],
        }
    )

    result = route_agent(state)

    assert result["active_agents"] == ["other_agent"]
