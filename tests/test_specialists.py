from cyberagent.agents.specialists import (
    crypto_agent,
    forensics_agent,
    misc_agent,
    other_agent,
    pwn_agent,
    reverse_agent,
    web_agent,
)
from cyberagent.graph import initial_state


def test_specialist_adds_finding_when_active():
    state = initial_state("1")
    state.update(
        {
            "title": "easy web",
            "predicted_categories": ["Web"],
            "active_agents": ["web_agent"],
        }
    )

    result = web_agent(state)

    assert result["findings"][-1]["agent"] == "web_agent"
    assert result["findings"][-1]["summary"] == "Web Agent received the challenge."


def test_specialist_returns_state_when_inactive():
    state = initial_state("1")
    state.update(
        {
            "title": "rsa warmup",
            "predicted_categories": ["Crypto"],
            "active_agents": ["crypto_agent"],
        }
    )

    result = web_agent(state)

    assert result is state
    assert result["findings"] == []


def test_all_specialist_nodes_can_receive_challenge():
    specialists = [
        ("web_agent", web_agent),
        ("pwn_agent", pwn_agent),
        ("reverse_agent", reverse_agent),
        ("crypto_agent", crypto_agent),
        ("misc_agent", misc_agent),
        ("forensics_agent", forensics_agent),
        ("other_agent", other_agent),
    ]

    for agent_name, agent_func in specialists:
        state = initial_state(agent_name)
        state["active_agents"] = [agent_name]

        result = agent_func(state)

        assert result["findings"][-1]["agent"] == agent_name
