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

    passed = evidence_gate_passes(signals)
    next_state: ChallengeState = {
        **state,
        "signals": signals,
        "evidence_gate_passed": passed,
    }
    next_state = add_trace_event(
        next_state,
        node="evidence_gate",
        event="evidence.gate",
        details={"passed": passed},
    )
    return add_finding(
        next_state,
        agent="evidence_gate",
        summary="Evidence gate passed." if passed else "Evidence gate blocked verification.",
        evidence={"passed": passed},
    )
