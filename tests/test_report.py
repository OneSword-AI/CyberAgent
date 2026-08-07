from cyberagent.evidence import add_finding
from cyberagent.graph import initial_state
from cyberagent.report import render_report
from cyberagent.tools import ToolResult, record_tool_output


def test_render_report_includes_core_sections():
    state = initial_state("web01")
    state.update(
        {
            "title": "login trail",
            "description": "A quiet login page.",
            "predicted_categories": ["Web"],
            "complexity": "simple",
            "reasoning_summary": "Looks like web auth bypass.",
            "next_agents": ["web_agent"],
            "active_agents": ["web_agent"],
            "candidate_flags": ["flag{demo}"],
        }
    )
    state = add_finding(state, agent="web_agent", summary="Found login endpoint")
    tool_result: ToolResult = {
        "tool": "http_get",
        "ok": True,
        "output": "ok",
        "error": None,
        "exit_code": 0,
    }
    state = record_tool_output(state, tool_result, caller="web_agent")

    report = render_report(state)

    assert "# CyberAgent Report" in report
    assert "- ID: web01" in report
    assert "- Title: login trail" in report
    assert "- Predicted Categories: Web" in report
    assert "- `flag{demo}`" in report
    assert "- [finding] web_agent: Found login endpoint" in report
    assert "- web_agent -> http_get: ok exit=0" in report


def test_render_report_handles_empty_lists():
    report = render_report(initial_state("empty"))

    assert "## Candidate Flags\n\nNone." in report
    assert "## Findings\n\nNone." in report
    assert "## Tool Outputs\n\nNone." in report
