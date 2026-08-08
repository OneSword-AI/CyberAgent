from collections.abc import Callable
from typing import Any

from langgraph.graph import END, StateGraph
from langgraph.types import Send

from cyberagent.agents.attachment_downloader import download_attachments
from cyberagent.agents.controller import run_controller_agent
from cyberagent.agents.evidence_gate import run_evidence_gate
from cyberagent.agents.flag_extractor import extract_candidate_flags
from cyberagent.agents.flag_verifier import verify_flag
from cyberagent.agents.foundation_node import run_foundation_agents
from cyberagent.agents.registry import SPECIALIST_NODES, SPECIALIST_ORDER
from cyberagent.agents.retry import retry_agent
from cyberagent.agents.router import route_agent
from cyberagent.agents.specialist_signals import publish_specialist_results
from cyberagent.models import ChallengeState
from cyberagent.providers import fetch_challenge


def build_graph():
    graph = StateGraph(ChallengeState)

    graph.add_node("fetch_challenge", _as_delta_node(fetch_challenge))
    graph.add_node("download_attachments", _as_delta_node(download_attachments))
    graph.add_node("foundation_agents", _as_delta_node(run_foundation_agents))
    graph.add_node("controller_agent", _as_delta_node(run_controller_agent))
    graph.add_node("route_agent", _as_delta_node(route_agent))
    for agent_name, agent_node in SPECIALIST_NODES.items():
        graph.add_node(agent_name, _as_delta_node(agent_node))
    graph.add_node(
        "publish_specialist_results",
        _as_delta_node(publish_specialist_results),
    )
    graph.add_node("extract_candidate_flags", _as_delta_node(extract_candidate_flags))
    graph.add_node("evidence_gate", _as_delta_node(run_evidence_gate))
    graph.add_node("verify_flag", _as_delta_node(verify_flag))
    graph.add_node("retry_agent", _as_delta_node(retry_agent))

    graph.set_entry_point("fetch_challenge")
    graph.add_edge("fetch_challenge", "download_attachments")
    graph.add_edge("download_attachments", "foundation_agents")
    graph.add_edge("foundation_agents", "controller_agent")
    graph.add_conditional_edges(
        "controller_agent",
        _controller_route,
        {
            "dispatch": "route_agent",
            "evaluate": "extract_candidate_flags",
        },
    )
    graph.add_conditional_edges("route_agent", _specialist_routes)
    for agent_name in SPECIALIST_ORDER:
        graph.add_edge(agent_name, "publish_specialist_results")
    graph.add_edge("publish_specialist_results", "controller_agent")
    graph.add_edge("extract_candidate_flags", "evidence_gate")
    graph.add_conditional_edges(
        "evidence_gate",
        _evidence_gate_route,
        {
            "verify": "verify_flag",
            "retry": "retry_agent",
            "end": END,
        },
    )
    graph.add_conditional_edges(
        "verify_flag",
        _verification_route,
        {
            "retry": "retry_agent",
            "end": END,
        },
    )
    graph.add_edge("retry_agent", "controller_agent")

    return graph.compile()


def initial_state(challenge_id: str) -> ChallengeState:
    return {
        "challenge_id": challenge_id,
        "attachments": [],
        "downloaded_attachments": [],
        "remote_targets": [],
        "predicted_categories": [],
        "next_agents": [],
        "active_agents": [],
        "plan": "",
        "plan_rationale": "",
        "controller_decisions": {},
        "controller_round": 0,
        "max_controller_rounds": 2,
        "stop_condition": "",
        "candidate_flags": [],
        "candidate_flag_records": [],
        "specialist_results": [],
        "published_specialist_results": 0,
        "findings": [],
        "verification_results": [],
        "failed_attempts": [],
        "tool_outputs": [],
        "trace": [],
        "signals": [],
        "artifacts_dir": "artifacts",
        "retry_count": 0,
        "max_retries": 1,
        "evidence_gate_passed": False,
    }


def _verification_route(state: ChallengeState) -> str:
    if state.get("final_flag"):
        return "end"
    if state.get("retry_count", 0) < state.get("max_retries", 1):
        return "retry"
    return "end"


def _controller_route(state: ChallengeState) -> str:
    if state.get("final_flag"):
        return "evaluate"
    if state.get("controller_round", 0) <= state.get("max_controller_rounds", 2):
        return "dispatch"
    return "evaluate"


def _evidence_gate_route(state: ChallengeState) -> str:
    if state.get("evidence_gate_passed"):
        return "verify"
    if state.get("retry_count", 0) < state.get("max_retries", 1):
        return "retry"
    return "end"


APPEND_FIELDS = {
    "downloaded_attachments",
    "findings",
    "verification_results",
    "failed_attempts",
    "tool_outputs",
    "trace",
    "signals",
    "candidate_flag_records",
    "specialist_results",
}


def _specialist_routes(state: ChallengeState):
    return [Send(agent_name, state) for agent_name in state.get("active_agents", [])]


def _as_delta_node(node: Callable[[ChallengeState], ChallengeState]):
    def wrapped(state: ChallengeState) -> dict[str, Any]:
        result = node(state)
        return _state_delta(state, result)

    return wrapped


def _state_delta(before: ChallengeState, after: ChallengeState) -> dict[str, Any]:
    delta: dict[str, Any] = {}
    for key, value in after.items():
        if before.get(key) == value:
            continue
        if key in APPEND_FIELDS and isinstance(before.get(key), list) and isinstance(value, list):
            previous = before.get(key, [])
            if value[: len(previous)] == previous:
                delta[key] = value[len(previous) :]
                continue
        delta[key] = value
    return delta
