from cyberagent.agents.constants import KNOWN_AGENT_NAMES
from cyberagent.agents.registry import SPECIALIST_NODES, SPECIALIST_ORDER
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

        assert result is state
