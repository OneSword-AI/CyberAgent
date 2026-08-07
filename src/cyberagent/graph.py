from langgraph.graph import END, StateGraph

from cyberagent.agents.llm_classifier import llm_classify_challenge
from cyberagent.agents.router import route_agent
from cyberagent.models import ChallengeState
from cyberagent.providers import fetch_challenge


def build_graph():
    graph = StateGraph(ChallengeState)

    graph.add_node("fetch_challenge", fetch_challenge)
    graph.add_node("classify_challenge", llm_classify_challenge)
    graph.add_node("route_agent", route_agent)

    graph.set_entry_point("fetch_challenge")
    graph.add_edge("fetch_challenge", "classify_challenge")
    graph.add_edge("classify_challenge", "route_agent")
    graph.add_edge("route_agent", END)

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
        "failed_attempts": [],
        "tool_outputs": [],
    }
