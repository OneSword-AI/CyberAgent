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
