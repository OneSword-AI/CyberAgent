from collections.abc import Callable
from typing import Any

from langgraph.graph import END, StateGraph

from cyberagent.agents.attachment_downloader import download_attachments
from cyberagent.agents.blackboard_specialists import run_blackboard_specialists
from cyberagent.agents.controller import run_controller_agent
from cyberagent.agents.evidence_gate import run_evidence_gate
from cyberagent.agents.flag_extractor import extract_candidate_flags
from cyberagent.agents.flag_submitter import submit_flag
from cyberagent.agents.flag_verifier import verify_flag
from cyberagent.agents.foundation_node import run_foundation_agents
from cyberagent.agents.retry import retry_agent
from cyberagent.budget import initial_budget, initial_budget_usage
from cyberagent.models import ChallengeState
from cyberagent.providers import fetch_challenge


def build_graph():
    graph = StateGraph(ChallengeState)

    graph.add_node("fetch_challenge", _as_delta_node(fetch_challenge))
    graph.add_node("download_attachments", _as_delta_node(download_attachments))
    graph.add_node("foundation_agents", _as_delta_node(run_foundation_agents))
    graph.add_node("controller_agent", _as_delta_node(run_controller_agent))
    graph.add_node("blackboard_specialists", _as_delta_node(run_blackboard_specialists))
    graph.add_node("extract_candidate_flags", _as_delta_node(extract_candidate_flags))
    graph.add_node("evidence_gate", _as_delta_node(run_evidence_gate))
    graph.add_node("verify_flag", _as_delta_node(verify_flag))
    graph.add_node("submit_flag", _as_delta_node(submit_flag))
    graph.add_node("retry_agent", _as_delta_node(retry_agent))

    graph.set_entry_point("fetch_challenge")
    graph.add_edge("fetch_challenge", "download_attachments")
    graph.add_edge("download_attachments", "foundation_agents")
    graph.add_edge("foundation_agents", "controller_agent")
    graph.add_conditional_edges(
        "controller_agent",
        _controller_route,
        {
            "dispatch": "blackboard_specialists",
            "evaluate": "extract_candidate_flags",
        },
    )
    graph.add_edge("blackboard_specialists", "controller_agent")
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
            "submit": "submit_flag",
            "retry": "retry_agent",
            "end": END,
        },
    )
    graph.add_conditional_edges(
        "submit_flag",
        _submission_route,
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
        "budget": initial_budget(),
        "budget_usage": initial_budget_usage(),
        "budget_exhausted": False,
        "stop_condition": "",
        "candidate_flags": [],
        "candidate_flag_records": [],
        "specialist_results": [],
        "published_specialist_results": 0,
        "findings": [],
        "verification_results": [],
        "submit_results": [],
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
        return "submit"
    if not state.get("budget_exhausted") and state.get("retry_count", 0) < state.get("max_retries", 1):
        return "retry"
    return "end"


def _submission_route(state: ChallengeState) -> str:
    if state.get("remote_accepted_flag"):
        return "end"
    if (
        not state.get("budget_exhausted")
        and _latest_submission_rejected(state)
        and state.get("retry_count", 0) < state.get("max_retries", 1)
    ):
        return "retry"
    return "end"


def _latest_submission_rejected(state: ChallengeState) -> bool:
    if not state.get("submit_results"):
        return False
    latest = state["submit_results"][-1]
    return latest.get("submitted") is True and latest.get("accepted") is False


def _controller_route(state: ChallengeState) -> str:
    if state.get("budget_exhausted"):
        return "evaluate"
    if state.get("final_flag"):
        return "evaluate"
    if state.get("controller_round", 0) <= state.get("max_controller_rounds", 2):
        return "dispatch"
    return "evaluate"


def _evidence_gate_route(state: ChallengeState) -> str:
    if state.get("evidence_gate_passed"):
        return "verify"
    if not state.get("budget_exhausted") and state.get("retry_count", 0) < state.get("max_retries", 1):
        return "retry"
    return "end"


APPEND_FIELDS = {
    "downloaded_attachments",
    "findings",
    "verification_results",
    "submit_results",
    "failed_attempts",
    "tool_outputs",
    "trace",
    "candidate_flag_records",
    "specialist_results",
}


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
