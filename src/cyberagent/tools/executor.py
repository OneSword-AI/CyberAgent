from cyberagent.models import ChallengeState
from cyberagent.tools.models import ToolResult


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

    return {
        **state,
        "tool_outputs": [*state.get("tool_outputs", []), tool_output],
    }
