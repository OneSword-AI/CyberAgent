from typing import Any

from cyberagent.evidence import add_finding
from cyberagent.flag import extract_flags, merge_candidate_flags
from cyberagent.models import ChallengeState
from cyberagent.signals import make_signal
from cyberagent.trace import add_trace_event


def extract_candidate_flags(state: ChallengeState) -> ChallengeState:
    """Extract candidate flags and record their evidence provenance."""
    discovered: list[str] = []
    new_records: list[dict[str, Any]] = []
    new_signals: list[dict[str, Any]] = []
    flag_format = state.get("flag_format")
    existing_records = state.get("candidate_flag_records", [])
    existing_keys = {_record_key(record) for record in existing_records}

    for source in _iter_flag_sources(state):
        flags = extract_flags(source["text"], flag_format)
        discovered = merge_candidate_flags(discovered, flags)
        for flag in flags:
            record_key = _source_key(flag, source)
            if record_key in existing_keys:
                continue
            signal = _make_evidence_signal(state, flag, source)
            new_signals.append(signal)
            new_records.append(_make_candidate_record(flag, source, signal["id"]))
            existing_keys.add(record_key)

    candidate_flags = merge_candidate_flags(state.get("candidate_flags", []), discovered)
    records = [*existing_records, *new_records]
    next_state: ChallengeState = {
        **state,
        "candidate_flags": candidate_flags,
        "candidate_flag_records": records,
        "signals": [*state.get("signals", []), *new_signals],
    }

    return add_finding(
        add_trace_event(
            next_state,
            node="extract_candidate_flags",
            event="flag.extract",
            details={
                "candidate_flags": discovered,
                "candidate_flag_records": len(new_records),
            },
        ),
        agent="flag_extractor",
        summary=f"Extracted {len(discovered)} candidate flag(s).",
        evidence={
            "candidate_flags": discovered,
            "candidate_flag_records": new_records,
            "evidence_signal_ids": [signal["id"] for signal in new_signals],
        },
    )


def _iter_flag_sources(state: ChallengeState):
    for index, output in enumerate(state.get("tool_outputs", [])):
        base = {
            "source_type": "tool_output",
            "source_index": index,
            "source_agent": output.get("caller", ""),
            "source_tool": output.get("tool", ""),
            "source_ok": output.get("ok"),
        }
        yield {**base, "source_field": "output", "text": str(output.get("output", ""))}
        yield {**base, "source_field": "error", "text": str(output.get("error", "") or "")}
        yield {**base, "source_field": "metadata", "text": _stringify(output.get("metadata", {}))}

    for index, finding in enumerate(state.get("findings", [])):
        if finding.get("agent") == "flag_extractor":
            continue
        base = {
            "source_type": "finding",
            "source_index": index,
            "source_agent": finding.get("agent", ""),
            "source_kind": finding.get("kind", "finding"),
        }
        yield {**base, "source_field": "summary", "text": str(finding.get("summary", ""))}
        yield {**base, "source_field": "evidence", "text": _stringify(finding.get("evidence", {}))}


def _make_evidence_signal(
    state: ChallengeState,
    flag: str,
    source: dict[str, Any],
) -> dict[str, Any]:
    provenance = "direct_tool" if source["source_type"] == "tool_output" else "inference"
    return make_signal(
        type="evidence",
        challenge_id=state.get("challenge_id", ""),
        source="flag_extractor",
        payload={
            "flag": flag,
            "source_type": source["source_type"],
            "source_index": source["source_index"],
            "source_field": source["source_field"],
            "source_agent": source.get("source_agent", ""),
            "source_tool": source.get("source_tool", ""),
            "source_ok": source.get("source_ok"),
        },
        provenance=provenance,
    )


def _make_candidate_record(flag: str, source: dict[str, Any], evidence_signal_id: str) -> dict[str, Any]:
    return {
        "flag": flag,
        "source_type": source["source_type"],
        "source_index": source["source_index"],
        "source_field": source["source_field"],
        "source_agent": source.get("source_agent", ""),
        "source_tool": source.get("source_tool", ""),
        "evidence_signal_id": evidence_signal_id,
    }


def _record_key(record: dict[str, Any]) -> tuple[Any, ...]:
    return (
        record.get("flag"),
        record.get("source_type"),
        record.get("source_index"),
        record.get("source_field"),
    )


def _source_key(flag: str, source: dict[str, Any]) -> tuple[Any, ...]:
    return (
        flag,
        source["source_type"],
        source["source_index"],
        source["source_field"],
    )


def _stringify(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{key}={_stringify(item)}" for key, item in value.items())
    if isinstance(value, list):
        return " ".join(_stringify(item) for item in value)
    return str(value)
