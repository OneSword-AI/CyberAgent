from cyberagent.agents.flag_extractor import extract_candidate_flags
from cyberagent.evidence import add_finding
from cyberagent.graph import initial_state
from cyberagent.tools import ToolResult, record_tool_output


def test_extract_candidate_flags_from_tool_outputs():
    state = initial_state("1")
    tool_result: ToolResult = {
        "tool": "shell",
        "ok": True,
        "output": "found flag{from_tool}",
        "error": None,
        "exit_code": 0,
    }
    state = record_tool_output(state, tool_result, caller="misc_agent")

    result = extract_candidate_flags(state)

    assert result["candidate_flags"] == ["flag{from_tool}"]
    assert result["findings"][-1]["agent"] == "flag_extractor"


def test_extract_candidate_flags_from_findings():
    state = initial_state("1")
    state = add_finding(state, agent="web_agent", summary="candidate CTF{from_finding}")

    result = extract_candidate_flags(state)

    assert result["candidate_flags"] == ["CTF{from_finding}"]


def test_extract_candidate_flags_merges_existing_flags():
    state = initial_state("1")
    state["candidate_flags"] = ["flag{old}"]
    tool_result: ToolResult = {
        "tool": "shell",
        "ok": True,
        "output": "flag{new} flag{old}",
        "error": None,
        "exit_code": 0,
    }
    state = record_tool_output(state, tool_result, caller="misc_agent")

    result = extract_candidate_flags(state)

    assert result["candidate_flags"] == ["flag{old}", "flag{new}"]
