import time
from typing import Any

from cyberagent.models import ChallengeState
from cyberagent.trace import add_trace_event

DEFAULT_BUDGET = {
    "max_tool_calls": 100,
    "max_http_requests": 50,
    "max_shell_commands": 30,
    "max_runtime_seconds": 300,
}


def initial_budget() -> dict[str, Any]:
    return dict(DEFAULT_BUDGET)


def initial_budget_usage() -> dict[str, Any]:
    return {
        "tool_calls": 0,
        "http_requests": 0,
        "shell_commands": 0,
        "started_at": time.time(),
    }


def budget_allows_tool(state: ChallengeState, tool: str) -> bool:
    budget = state.get("budget", {})
    usage = state.get("budget_usage", {})
    if _runtime_exhausted(budget, usage):
        return False
    if usage.get("tool_calls", 0) >= budget.get("max_tool_calls", DEFAULT_BUDGET["max_tool_calls"]):
        return False
    if _is_http(tool) and usage.get("http_requests", 0) >= budget.get("max_http_requests", DEFAULT_BUDGET["max_http_requests"]):
        return False
    return not (
        tool == "shell"
        and usage.get("shell_commands", 0) >= budget.get("max_shell_commands", DEFAULT_BUDGET["max_shell_commands"])
    )


def budget_exhaustion_reason(state: ChallengeState, tool: str | None = None) -> str:
    budget = state.get("budget", {})
    usage = state.get("budget_usage", {})
    if _runtime_exhausted(budget, usage):
        return "max_runtime_seconds exhausted"
    if usage.get("tool_calls", 0) >= budget.get("max_tool_calls", DEFAULT_BUDGET["max_tool_calls"]):
        return "max_tool_calls exhausted"
    if (tool is None or _is_http(tool)) and usage.get("http_requests", 0) >= budget.get("max_http_requests", DEFAULT_BUDGET["max_http_requests"]):
        return "max_http_requests exhausted"
    if (tool is None or tool == "shell") and usage.get("shell_commands", 0) >= budget.get("max_shell_commands", DEFAULT_BUDGET["max_shell_commands"]):
        return "max_shell_commands exhausted"
    return ""


def record_tool_budget_usage(state: ChallengeState, tool_outputs: list[dict]) -> ChallengeState:
    usage = dict(state.get("budget_usage", initial_budget_usage()))
    for output in tool_outputs:
        if output.get("metadata", {}).get("budget_denied"):
            continue
        tool = output.get("tool", "")
        usage["tool_calls"] = usage.get("tool_calls", 0) + 1
        if _is_http(tool):
            usage["http_requests"] = usage.get("http_requests", 0) + 1
        if tool == "shell":
            usage["shell_commands"] = usage.get("shell_commands", 0) + 1

    next_state: ChallengeState = {**state, "budget_usage": usage}
    exhausted = is_budget_exhausted(next_state)
    next_state["budget_exhausted"] = exhausted
    if exhausted and not state.get("budget_exhausted"):
        next_state = add_trace_event(
            next_state,
            node="budget",
            event="budget.exhausted",
            details={"reason": budget_exhaustion_reason(next_state)},
        )
    return next_state


def is_budget_exhausted(state: ChallengeState) -> bool:
    return bool(state.get("budget_exhausted")) or bool(budget_exhaustion_reason(state))


def budget_denied_tool_result(tool: str, reason: str) -> dict:
    return {
        "tool": tool,
        "ok": False,
        "output": "",
        "error": f"budget denied: {reason}",
        "exit_code": None,
        "metadata": {"budget_denied": True, "reason": reason},
    }


def _is_http(tool: str) -> bool:
    return tool.startswith("http_")


def _runtime_exhausted(budget: dict, usage: dict) -> bool:
    max_seconds = budget.get("max_runtime_seconds", DEFAULT_BUDGET["max_runtime_seconds"])
    started_at = usage.get("started_at")
    return bool(started_at and time.time() - started_at >= max_seconds)
