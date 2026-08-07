from typing import Any

from cyberagent.evidence import add_finding
from cyberagent.flag import extract_flags, merge_candidate_flags
from cyberagent.models import ChallengeState
from cyberagent.trace import add_trace_event


def extract_candidate_flags(state: ChallengeState) -> ChallengeState:
    """Extract candidate flags from findings and tool outputs."""
    discovered: list[str] = []
    flag_format = state.get("flag_format")

    for text in _iter_flag_sources(state):
        discovered = merge_candidate_flags(discovered, extract_flags(text, flag_format))

    candidate_flags = merge_candidate_flags(state.get("candidate_flags", []), discovered)
    next_state: ChallengeState = {
        **state,
        "candidate_flags": candidate_flags,
    }

    return add_finding(
        add_trace_event(
            next_state,
            node="extract_candidate_flags",
            event="flag.extract",
            details={"candidate_flags": discovered},
        ),
        agent="flag_extractor",
        summary=f"Extracted {len(discovered)} candidate flag(s).",
        evidence={"candidate_flags": discovered},
    )


def _iter_flag_sources(state: ChallengeState):
    for output in state.get("tool_outputs", []):
        yield str(output.get("output", ""))
        yield str(output.get("error", "") or "")
        yield _stringify(output.get("metadata", {}))

    for finding in state.get("findings", []):
        yield str(finding.get("summary", ""))
        yield _stringify(finding.get("evidence", {}))


def _stringify(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{key}={_stringify(item)}" for key, item in value.items())
    if isinstance(value, list):
        return " ".join(_stringify(item) for item in value)
    return str(value)
