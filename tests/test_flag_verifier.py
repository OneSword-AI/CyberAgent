from cyberagent.agents.flag_verifier import verify_flag
from cyberagent.graph import initial_state


def test_verify_flag_accepts_default_flag_pattern():
    state = initial_state("1")
    state["candidate_flags"] = ["flag{demo}"]

    result = verify_flag(state)

    assert result["final_flag"] == "flag{demo}"
    assert result["verification_results"][-1]["valid"] is True
    assert result["findings"][-1]["agent"] == "verify_flag"


def test_verify_flag_uses_custom_flag_format():
    state = initial_state("1")
    state["flag_format"] = r"FLAG-[0-9]+"
    state["candidate_flags"] = ["flag{demo}", "FLAG-123"]

    result = verify_flag(state)

    assert result["final_flag"] == "FLAG-123"
    assert result["verification_results"][0]["valid"] is False
    assert result["verification_results"][1]["valid"] is True


def test_verify_flag_records_no_acceptance():
    state = initial_state("1")
    state["candidate_flags"] = ["not-a-flag"]

    result = verify_flag(state)

    assert "final_flag" not in result
    assert result["verification_results"][-1]["valid"] is False
    assert result["trace"][-1]["event"] == "flag.verify"


def test_verify_flag_records_candidate_evidence_reference():
    state = initial_state("1")
    state["candidate_flags"] = ["flag{demo}"]
    state["candidate_flag_records"] = [
        {
            "flag": "flag{demo}",
            "source_type": "tool_output",
            "source_index": 0,
            "source_field": "output",
            "source_agent": "web_agent",
            "source_tool": "http_get",
            "evidence_signal_id": "evidence-1",
        }
    ]

    result = verify_flag(state)

    verification = result["verification_results"][-1]
    assert verification["evidence_signal_id"] == "evidence-1"
    assert verification["source_agent"] == "web_agent"
    assert verification["source_tool"] == "http_get"
