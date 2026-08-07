from langgraph.graph import END, StateGraph

from cyberagent.agents.flag_extractor import extract_candidate_flags
from cyberagent.agents.llm_classifier import llm_classify_challenge
from cyberagent.agents.router import route_agent
from cyberagent.agents.specialists import (
    crypto_agent,
    forensics_agent,
    misc_agent,
    other_agent,
    pwn_agent,
    reverse_agent,
    web_agent,
)
from cyberagent.models import ChallengeState
from cyberagent.providers import fetch_challenge


def build_graph():
    graph = StateGraph(ChallengeState)

    graph.add_node("fetch_challenge", fetch_challenge)
    graph.add_node("classify_challenge", llm_classify_challenge)
    graph.add_node("route_agent", route_agent)
    graph.add_node("web_agent", web_agent)
    graph.add_node("pwn_agent", pwn_agent)
    graph.add_node("reverse_agent", reverse_agent)
    graph.add_node("crypto_agent", crypto_agent)
    graph.add_node("misc_agent", misc_agent)
    graph.add_node("forensics_agent", forensics_agent)
    graph.add_node("other_agent", other_agent)
    graph.add_node("extract_candidate_flags", extract_candidate_flags)

    graph.set_entry_point("fetch_challenge")
    graph.add_edge("fetch_challenge", "classify_challenge")
    graph.add_edge("classify_challenge", "route_agent")
    graph.add_edge("route_agent", "web_agent")
    graph.add_edge("web_agent", "pwn_agent")
    graph.add_edge("pwn_agent", "reverse_agent")
    graph.add_edge("reverse_agent", "crypto_agent")
    graph.add_edge("crypto_agent", "misc_agent")
    graph.add_edge("misc_agent", "forensics_agent")
    graph.add_edge("forensics_agent", "other_agent")
    graph.add_edge("other_agent", "extract_candidate_flags")
    graph.add_edge("extract_candidate_flags", END)

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
