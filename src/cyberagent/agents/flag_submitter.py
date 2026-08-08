from cyberagent.evidence import add_finding
from cyberagent.models import ChallengeState
from cyberagent.safety import L0SafetyGate
from cyberagent.submitters import get_submit_provider
from cyberagent.trace import add_trace_event


def submit_flag(state: ChallengeState) -> ChallengeState:
    """Optionally submit a locally accepted flag to a remote platform."""
    flag = state.get("final_flag")
    if not flag:
        return state
    if _already_submitted(state, flag):
        return add_trace_event(
            state,
            node="submit_flag",
            event="flag.submit.skip",
            details={"reason": "already submitted"},
        )

    decision = L0SafetyGate().evaluate(
        action_type="flag.submit",
        caller="submit_flag",
        params={"challenge_id": state.get("challenge_id", ""), "flag": flag},
    )
    if not decision.allow:
        result = {
            "submitted": False,
            "accepted": None,
            "status": "denied",
            "message": f"L0 denied: {decision.reason}",
            "raw_response": None,
            "flag": flag,
            "provider": "l0",
        }
    else:
        provider = get_submit_provider()
        provider_result = provider.submit(state.get("challenge_id", ""), flag)
        result = {
            **provider_result,
            "flag": flag,
            "provider": provider.name,
        }

    next_state: ChallengeState = {
        **state,
        "submit_results": [*state.get("submit_results", []), result],
    }
    if result["accepted"] is True:
        next_state["remote_accepted_flag"] = flag

    next_state = add_trace_event(
        next_state,
        node="submit_flag",
        event="flag.submit",
        details={
            "provider": result["provider"],
            "submitted": result["submitted"],
            "accepted": result["accepted"],
            "status": result["status"],
        },
    )
    return add_finding(
        next_state,
        agent="submit_flag",
        summary=_summary(result),
        evidence={"submit_result": result},
    )


def _already_submitted(state: ChallengeState, flag: str) -> bool:
    return any(result.get("flag") == flag and result.get("submitted") for result in state.get("submit_results", []))


def _summary(result: dict) -> str:
    if result["accepted"] is True:
        return f"Remote platform accepted flag: {result['flag']}"
    if result["submitted"]:
        return f"Remote platform rejected flag: {result['flag']}"
    return f"Remote flag submission skipped: {result['message']}"
