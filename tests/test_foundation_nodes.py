from cyberagent.agents.evidence_gate import run_evidence_gate
from cyberagent.agents.foundation_node import run_foundation_agents
from cyberagent.graph import initial_state
from cyberagent.tools import ToolResult, record_tool_output


def test_run_foundation_agents_adds_structured_signals():
    state = initial_state("fn01")
    state["title"] = "demo"

    result = run_foundation_agents(state)

    signal_types = [signal["type"] for signal in result["signals"]]
    assert "challenge_input" in signal_types
    assert "observation" in signal_types
    assert "memory_prior" in signal_types
    assert "hypothesis" in signal_types
    assert "critic_report" in signal_types
    assert result["findings"][-1]["agent"] == "foundation_agents"

    signals = result["signals"]
    by_type = {signal["type"]: signal for signal in signals}
    assert len(signals) == 5
    assert by_type["challenge_input"]["status"] == "processed"
    assert by_type["observation"]["status"] == "processed"
    assert by_type["hypothesis"]["status"] == "processed"
    assert by_type["memory_prior"]["status"] == "pending"
    assert by_type["critic_report"]["status"] == "pending"
    assert by_type["observation"]["parent_ids"] == [by_type["challenge_input"]["id"]]
    assert by_type["memory_prior"]["parent_ids"] == [by_type["challenge_input"]["id"]]
    assert by_type["hypothesis"]["parent_ids"] == [by_type["observation"]["id"]]
    assert by_type["critic_report"]["parent_ids"] == [by_type["hypothesis"]["id"]]


def test_run_evidence_gate_passes_with_critic_and_tool_output():
    state = run_foundation_agents(initial_state("gate01"))
    tool_result: ToolResult = {
        "tool": "http_get",
        "ok": True,
        "output": "flag{demo}",
        "error": None,
        "exit_code": 0,
    }
    state = record_tool_output(state, tool_result, caller="web_agent")

    result = run_evidence_gate(state)

    assert result["evidence_gate_passed"] is True
    assert result["findings"][-1]["agent"] == "evidence_gate"


def test_run_evidence_gate_blocks_without_direct_evidence():
    state = run_foundation_agents(initial_state("gate01"))

    result = run_evidence_gate(state)

    assert result["evidence_gate_passed"] is False


def test_run_evidence_gate_blocks_unproven_candidate_flag():
    state = run_foundation_agents(initial_state("gate01"))
    tool_result: ToolResult = {
        "tool": "http_get",
        "ok": True,
        "output": "response body",
        "error": None,
        "exit_code": 0,
    }
    state = record_tool_output(state, tool_result, caller="web_agent")
    state["candidate_flags"] = ["flag{unproven}"]

    result = run_evidence_gate(state)

    assert result["evidence_gate_passed"] is False
    assert result["findings"][-1]["evidence"]["candidate_flag_chains_passed"] is False
