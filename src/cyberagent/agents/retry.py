from cyberagent.evidence import add_finding
from cyberagent.models import ChallengeState
from cyberagent.trace import add_trace_event


def retry_agent(state: ChallengeState) -> ChallengeState:
    """Record a failed attempt and schedule another solving pass."""
    retry_count = state.get("retry_count", 0) + 1
    failed_attempt = {
        "retry": retry_count,
        "candidate_flags": state.get("candidate_flags", []),
        "verification_results": state.get("verification_results", []),
        "reason": "no valid flag accepted",
    }
    next_state: ChallengeState = {
        **state,
        "retry_count": retry_count,
        "failed_attempts": [*state.get("failed_attempts", []), failed_attempt],
    }
    next_state = add_trace_event(
        next_state,
        node="retry_agent",
        event="retry.schedule",
        details={
            "retry_count": retry_count,
            "max_retries": state.get("max_retries", 1),
        },
    )
    return add_finding(
        next_state,
        agent="retry_agent",
        summary=f"Retry scheduled ({retry_count}/{state.get('max_retries', 1)}).",
        evidence=failed_attempt,
    )
