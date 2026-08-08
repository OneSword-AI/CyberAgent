import re

from cyberagent.evidence import add_finding
from cyberagent.flag import DEFAULT_FLAG_PATTERN
from cyberagent.models import ChallengeState
from cyberagent.trace import add_trace_event


def verify_flag(state: ChallengeState) -> ChallengeState:
    """Verify candidate flags locally using format rules."""
    results = [
        _with_candidate_record(
            _verify_one(flag, state.get("flag_format")),
            state.get("candidate_flag_records", []),
        )
        for flag in state.get("candidate_flags", [])
    ]
    accepted = next((result["flag"] for result in results if result["valid"]), None)

    next_state: ChallengeState = {
        **state,
        "verification_results": [*state.get("verification_results", []), *results],
    }
    if accepted:
        next_state["final_flag"] = accepted

    next_state = add_trace_event(
        next_state,
        node="verify_flag",
        event="flag.verify",
        details={
            "checked": len(results),
            "accepted": accepted,
        },
    )
    return add_finding(
        next_state,
        agent="verify_flag",
        summary=(
            f"Accepted candidate flag: {accepted}"
            if accepted
            else f"Verified {len(results)} candidate flag(s); none accepted."
        ),
        evidence={"verification_results": results},
    )


def _verify_one(flag: str, flag_format: str | None) -> dict:
    if flag_format:
        valid = re.fullmatch(flag_format, flag) is not None
        return {
            "flag": flag,
            "valid": valid,
            "method": "flag_format",
            "reason": "matches flag_format" if valid else "does not match flag_format",
        }

    valid = DEFAULT_FLAG_PATTERN.fullmatch(flag) is not None
    return {
        "flag": flag,
        "valid": valid,
        "method": "default_pattern",
        "reason": "matches default pattern" if valid else "does not match default pattern",
    }


def _with_candidate_record(result: dict, records: list[dict]) -> dict:
    record = next((item for item in records if item.get("flag") == result["flag"]), None)
    if record is None:
        return result
    return {
        **result,
        "evidence_signal_id": record.get("evidence_signal_id"),
        "source_type": record.get("source_type"),
        "source_index": record.get("source_index"),
        "source_field": record.get("source_field"),
        "source_agent": record.get("source_agent"),
        "source_tool": record.get("source_tool"),
    }
