from typing import Any

from cyberagent.safety import L0SafetyGate
from cyberagent.tools.adapter import FunctionToolAdapter, ToolRegistry
from cyberagent.tools.filesystem import inspect_file
from cyberagent.tools.http import http_get
from cyberagent.tools.models import ToolResult
from cyberagent.tools.shell import run_shell


TOOL_ACTION_TYPES = {
    "http_get": "http.request",
    "shell": "shell.run",
    "file_inspect": "file.inspect",
}


def build_default_tool_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        FunctionToolAdapter(
            name="http_get",
            description="Perform a bounded HTTP/HTTPS GET request.",
            input_schema={"required": ["url"]},
            handler=lambda request: http_get(
                request["url"],
                headers=request.get("headers"),
                timeout=request.get("timeout", 10),
                max_chars=request.get("max_chars", 2000),
            ),
        )
    )
    registry.register(
        FunctionToolAdapter(
            name="shell",
            description="Run an unrestricted local shell command.",
            input_schema={"required": ["command"]},
            handler=lambda request: run_shell(
                request["command"],
                cwd=request.get("cwd"),
                timeout=request.get("timeout", 30),
                env=request.get("env"),
                max_chars=request.get("max_chars", 4000),
            ),
        )
    )
    registry.register(
        FunctionToolAdapter(
            name="file_inspect",
            description="Inspect a local file and return metadata.",
            input_schema={"required": ["path"]},
            handler=lambda request: inspect_file(
                request["path"],
                max_bytes=request.get("max_bytes", 512),
            ),
        )
    )
    return registry


def execute_tool(
    name: str,
    request: dict[str, Any],
    *,
    caller: str,
    registry: ToolRegistry | None = None,
    safety_gate: L0SafetyGate | None = None,
) -> ToolResult:
    registry = registry or build_default_tool_registry()
    safety_gate = safety_gate or L0SafetyGate()
    action_type = TOOL_ACTION_TYPES.get(name, "unknown")
    decision = safety_gate.evaluate(action_type=action_type, caller=caller, params=request)
    if not decision.allow:
        return {
            "tool": name,
            "ok": False,
            "output": "",
            "error": f"L0 denied: {decision.reason}",
            "exit_code": None,
            "metadata": {
                "action_type": action_type,
                "caller": caller,
                "request": request,
            },
        }
    return registry.execute(name, request)
