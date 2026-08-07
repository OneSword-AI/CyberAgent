from langgraph.graph import END, StateGraph

from cyberagent.agents.flag_extractor import extract_candidate_flags
from cyberagent.agents.flag_verifier import verify_flag
from cyberagent.agents.llm_classifier import llm_classify_challenge
from cyberagent.agents.registry import SPECIALIST_NODES, SPECIALIST_ORDER
from cyberagent.agents.router import route_agent
from cyberagent.models import ChallengeState
from cyberagent.providers import fetch_challenge


def build_graph():
    graph = StateGraph(ChallengeState)

    graph.add_node("fetch_challenge", fetch_challenge)
    graph.add_node("classify_challenge", llm_classify_challenge)
    graph.add_node("route_agent", route_agent)
    for agent_name, agent_node in SPECIALIST_NODES.items():
        graph.add_node(agent_name, agent_node)
    graph.add_node("extract_candidate_flags", extract_candidate_flags)
    graph.add_node("verify_flag", verify_flag)

    graph.set_entry_point("fetch_challenge")
    graph.add_edge("fetch_challenge", "classify_challenge")
    graph.add_edge("classify_challenge", "route_agent")
    graph.add_edge("route_agent", SPECIALIST_ORDER[0])
    for current_agent, next_agent in zip(SPECIALIST_ORDER, SPECIALIST_ORDER[1:]):
        graph.add_edge(current_agent, next_agent)
    graph.add_edge(SPECIALIST_ORDER[-1], "extract_candidate_flags")
    graph.add_edge("extract_candidate_flags", "verify_flag")
    graph.add_edge("verify_flag", END)

    return graph.compile()


def initial_state(challenge_id: str) -> ChallengeState:
    return {
        "challenge_id": challenge_id,
        "attachments": [],
        "remote_targets": [],
        "predicted_categories": [],
        "next_agents": [],
        "active_agents": [],
        "candidate_flags": [],
        "findings": [],
        "verification_results": [],
        "failed_attempts": [],
        "tool_outputs": [],
        "trace": [],
    }
