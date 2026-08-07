from cyberagent.models import ChallengeState
from cyberagent.tools.models import ToolResult
from cyberagent.trace import add_trace_event


def record_tool_output(
    state: ChallengeState,
    result: ToolResult,
    *,
    caller: str,
) -> ChallengeState:
    """Append a normalized tool result to ChallengeState."""
    tool_output = {
        "caller": caller,
        "tool": result["tool"],
        "ok": result["ok"],
        "output": result["output"],
        "error": result["error"],
        "exit_code": result["exit_code"],
        "metadata": result.get("metadata", {}),
    }

    next_state: ChallengeState = {
        **state,
        "tool_outputs": [*state.get("tool_outputs", []), tool_output],
    }
    return add_trace_event(
        next_state,
        node=caller,
        event="tool.output",
        details={
            "tool": result["tool"],
            "ok": result["ok"],
            "exit_code": result["exit_code"],
        },
    )
