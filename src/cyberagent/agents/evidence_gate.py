from cyberagent.evidence import add_finding
from cyberagent.evidence_gate import evidence_gate_passes
from cyberagent.models import ChallengeState
from cyberagent.signals import make_signal
from cyberagent.trace import add_trace_event


def run_evidence_gate(state: ChallengeState) -> ChallengeState:
    """Evaluate whether candidate conclusions have enough evidence."""
    signals = list(state.get("signals", []))
    for output in state.get("tool_outputs", []):
        if output.get("ok"):
            signals.append(
                make_signal(
                    type="evidence",
                    challenge_id=state.get("challenge_id", ""),
                    source=output.get("caller", "tool"),
                    payload=output,
                    provenance="direct_tool",
                )
            )

    chain_passed = _candidate_flag_chains_pass(state, signals)
    passed = evidence_gate_passes(signals) and chain_passed
    next_state: ChallengeState = {
        **state,
        "signals": signals,
        "evidence_gate_passed": passed,
    }
    next_state = add_trace_event(
        next_state,
        node="evidence_gate",
        event="evidence.gate",
        details={"passed": passed, "candidate_flag_chains_passed": chain_passed},
    )
    return add_finding(
        next_state,
        agent="evidence_gate",
        summary="Evidence gate passed." if passed else "Evidence gate blocked verification.",
        evidence={
            "passed": passed,
            "candidate_flag_chains_passed": chain_passed,
        },
    )


def _candidate_flag_chains_pass(state: ChallengeState, signals: list[dict]) -> bool:
    candidate_flags = state.get("candidate_flags", [])
    if not candidate_flags:
        return True

    records = state.get("candidate_flag_records", [])
    signal_ids = {
        signal["id"]
        for signal in signals
        if signal["type"] == "evidence"
        and signal["payload"].get("flag") in candidate_flags
    }
    flags_with_records = {
        record["flag"]
        for record in records
        if record.get("evidence_signal_id") in signal_ids
    }
    return all(flag in flags_with_records for flag in candidate_flags)
