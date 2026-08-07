from cyberagent.graph import initial_state
from cyberagent.tools import ToolResult, record_tool_output


def test_record_tool_output_appends_normalized_result():
    state = initial_state("1")
    result: ToolResult = {
        "tool": "mock_file",
        "ok": True,
        "output": "flag-like string found",
        "error": None,
        "exit_code": 0,
        "metadata": {"path": "artifact.txt"},
    }

    next_state = record_tool_output(state, result, caller="web_agent")

    assert next_state["tool_outputs"] == [
        {
            "caller": "web_agent",
            "tool": "mock_file",
            "ok": True,
            "output": "flag-like string found",
            "error": None,
            "exit_code": 0,
            "metadata": {"path": "artifact.txt"},
        }
    ]
    assert state["tool_outputs"] == []


def test_record_tool_output_defaults_metadata():
    state = initial_state("1")
    result: ToolResult = {
        "tool": "mock_http",
        "ok": False,
        "output": "",
        "error": "connection refused",
        "exit_code": None,
    }

    next_state = record_tool_output(state, result, caller="web_agent")

    assert next_state["tool_outputs"][0]["metadata"] == {}
