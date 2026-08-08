from cyberagent.agents.constants import KNOWN_AGENT_NAMES
from cyberagent.agents.registry import (
    SPECIALIST_AGENTS,
    SPECIALIST_NODES,
    SPECIALIST_ORDER,
)
from cyberagent.graph import initial_state


def test_specialist_registry_covers_known_agent_names():
    assert set(SPECIALIST_NODES) == set(KNOWN_AGENT_NAMES)


def test_specialist_order_matches_registry_order():
    assert SPECIALIST_ORDER == tuple(SPECIALIST_NODES)


def test_registered_specialist_nodes_are_callable():
    for agent_name, agent_node in SPECIALIST_NODES.items():
        state = initial_state(agent_name)
        state["active_agents"] = []

        result = agent_node(state)

        assert result["specialist_results"][0]["agent"] == agent_name
        assert result["specialist_results"][0]["status"] == "skipped"


def test_registered_specialist_agents_return_normalized_results():
    for agent_name, agent in SPECIALIST_AGENTS.items():
        state = initial_state(agent_name)
        state["active_agents"] = [agent_name]

        result = agent(state)

        assert result["agent"] == agent_name
        assert result["status"] in {"completed", "skipped", "failed"}
        assert isinstance(result["findings"], list)
        assert isinstance(result["candidate_flags"], list)
        assert isinstance(result["tool_outputs"], list)
        assert isinstance(result["next_actions"], list)
