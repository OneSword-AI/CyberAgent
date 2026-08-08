from cyberagent.budget import (
    budget_allows_tool,
    budget_denied_tool_result,
    budget_exhaustion_reason,
    record_tool_budget_usage,
)
from cyberagent.graph import initial_state


def test_budget_allows_tool_until_limit_is_reached():
    state = initial_state("budget01")
    state["budget"] = {**state["budget"], "max_http_requests": 1}
    state["budget_usage"] = {**state["budget_usage"], "http_requests": 1}

    assert budget_allows_tool(state, "http_get") is False
    assert budget_exhaustion_reason(state, "http_get") == "max_http_requests exhausted"


def test_record_tool_budget_usage_marks_exhaustion():
    state = initial_state("budget01")
    state["budget"] = {**state["budget"], "max_tool_calls": 1}

    result = record_tool_budget_usage(
        state,
        [{"tool": "http_get"}, {"tool": "shell"}],
    )

    assert result["budget_usage"]["tool_calls"] == 2
    assert result["budget_usage"]["http_requests"] == 1
    assert result["budget_usage"]["shell_commands"] == 1
    assert result["budget_exhausted"] is True
    assert result["trace"][-1]["event"] == "budget.exhausted"


def test_budget_denied_outputs_are_not_counted_as_executed_tools():
    state = initial_state("budget01")
    result = record_tool_budget_usage(
        state,
        [
            {"tool": "http_get"},
            budget_denied_tool_result("http_get", "max_http_requests exhausted"),
        ],
    )

    assert result["budget_usage"]["tool_calls"] == 1
    assert result["budget_usage"]["http_requests"] == 1


def test_budget_denied_tool_result_is_normalized():
    result = budget_denied_tool_result("http_get", "max_http_requests exhausted")

    assert result["ok"] is False
    assert result["error"] == "budget denied: max_http_requests exhausted"
    assert result["metadata"]["budget_denied"] is True
