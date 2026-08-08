from cyberagent.blackboard import Blackboard
from cyberagent.evidence import add_finding
from cyberagent.models import ChallengeState, SpecialistResult
from cyberagent.signals import make_signal
from cyberagent.trace import add_trace_event


def publish_specialist_results(state: ChallengeState) -> ChallengeState:
    """Publish new specialist results to the shared blackboard snapshot."""
    results = state.get("specialist_results", [])
    published = state.get("published_specialist_results", 0)
    board = Blackboard(state.get("signals", []))
    new_results = results[published:]

    for result in new_results:
        board.post(_result_signal(state, result))

    next_state: ChallengeState = {
        **state,
        "signals": board.snapshot(),
        "published_specialist_results": published + len(new_results),
    }
    next_state = add_trace_event(
        next_state,
        node="publish_specialist_results",
        event="blackboard.publish",
        details={"published": len(new_results)},
    )
    return add_finding(
        next_state,
        agent="publish_specialist_results",
        summary=f"Published {len(new_results)} specialist result signal(s).",
        evidence={
            "published": len(new_results),
            "recipients": ["controller_agent"],
        },
    )


def _result_signal(
    state: ChallengeState,
    result: SpecialistResult,
    *,
    parent_ids: list[str] | None = None,
) -> dict:
    return make_signal(
        type="specialist_result",
        challenge_id=state.get("challenge_id", ""),
        source=result["agent"],
        payload={
            "status": result["status"],
            "summary": result["summary"],
            "findings": result["findings"],
            "candidate_flags": result["candidate_flags"],
            "tool_outputs": result["tool_outputs"],
            "next_actions": result["next_actions"],
            **({"error": result["error"]} if "error" in result else {}),
        },
        provenance="direct_tool" if result["tool_outputs"] else "inference",
        parent_ids=parent_ids,
        recipients=["controller_agent"],
    )


def make_specialist_result_signal(
    state: ChallengeState,
    result: SpecialistResult,
    *,
    parent_ids: list[str] | None = None,
) -> dict:
    """Create a blackboard signal for a normalized specialist result."""
    return _result_signal(state, result, parent_ids=parent_ids)
