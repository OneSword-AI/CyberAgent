from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from cyberagent.tools.models import ToolResult


@runtime_checkable
class ToolAdapter(Protocol):
    name: str

    def describe(self) -> dict[str, Any]:
        """Return metadata describing the tool."""
        ...

    def execute(self, request: dict[str, Any]) -> ToolResult:
        """Execute a tool request and return a normalized result."""
        ...


@dataclass
class FunctionToolAdapter:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], ToolResult]

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }

    def execute(self, request: dict[str, Any]) -> ToolResult:
        return self.handler(request)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        if adapter.name in self._tools:
            raise ValueError(f"tool adapter already registered: {adapter.name}")
        self._tools[adapter.name] = adapter

    def get(self, name: str) -> ToolAdapter:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool adapter: {name}") from exc

    def describe_all(self) -> list[dict[str, Any]]:
        return [adapter.describe() for adapter in self._tools.values()]

    def execute(self, name: str, request: dict[str, Any]) -> ToolResult:
        return self.get(name).execute(request)
