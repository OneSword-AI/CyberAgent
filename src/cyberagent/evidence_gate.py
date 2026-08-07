from cyberagent.signals import Signal


def evidence_gate_passes(signals: list[Signal]) -> bool:
    """Require direct evidence and independent critic approval."""
    has_direct_evidence = any(
        signal["type"] == "evidence" and signal["provenance"] == "direct_tool"
        for signal in signals
    )
    has_critic_approval = any(
        signal["type"] == "critic_report"
        and signal["payload"].get("verdict") == "approved"
        for signal in signals
    )
    return has_direct_evidence and has_critic_approval
