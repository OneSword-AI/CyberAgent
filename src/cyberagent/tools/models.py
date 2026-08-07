from typing import Any, NotRequired, TypedDict


class ToolResult(TypedDict):
    tool: str
    ok: bool
    output: str
    error: str | None
    exit_code: int | None
    metadata: NotRequired[dict[str, Any]]
