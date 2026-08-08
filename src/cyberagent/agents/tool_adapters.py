from collections.abc import Callable
from typing import Any, Protocol, TypedDict, runtime_checkable

from cyberagent.models import ChallengeState
from cyberagent.tools import ToolResult, execute_tool


class SpecialistAdapterResult(TypedDict):
    summary: str
    findings: list[dict[str, Any]]
    candidate_flags: list[str]
    tool_outputs: list[dict[str, Any]]
    next_actions: list[dict[str, Any]]


@runtime_checkable
class SpecialistToolAdapter(Protocol):
    name: str

    def describe(self) -> dict[str, Any]:
        ...

    def execute(self, state: ChallengeState) -> SpecialistAdapterResult:
        ...


class WebToolAdapter:
    name = "web"

    def __init__(
        self,
        *,
        tool_executor: Callable[..., ToolResult] = execute_tool,
    ) -> None:
        self._tool_executor = tool_executor

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Inspect the first configured HTTP/HTTPS challenge target.",
            "capabilities": ["http_get"],
        }

    def execute(self, state: ChallengeState) -> SpecialistAdapterResult:
        target = _first_remote_target(state)
        result = (
            self._tool_executor("http_get", {"url": target}, caller="web_agent")
            if target
            else _missing_target_result()
        )
        output = _tool_output(result, caller="web_agent")
        return {
            "summary": "Web Adapter inspected the first remote target.",
            "findings": [],
            "candidate_flags": [],
            "tool_outputs": [output],
            "next_actions": [],
        }


class PlaceholderToolAdapter:
    """MVP adapter contract for a domain without a real scanner."""

    def __init__(self, name: str, domain: str) -> None:
        self.name = name
        self._domain = domain

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": f"Adapter boundary for {self._domain} solving tools.",
            "capabilities": [],
        }

    def execute(self, state: ChallengeState) -> SpecialistAdapterResult:
        return {
            "summary": (
                f"{self._domain} Adapter received the challenge; "
                "no domain tool is configured yet."
            ),
            "findings": [],
            "candidate_flags": [],
            "tool_outputs": [],
            "next_actions": [
                {
                    "kind": "tool_adapter",
                    "reason": "domain-specific solving tools are not configured",
                }
            ],
        }


class SpecialistToolAdapterRegistry:
    def __init__(self, adapters: list[SpecialistToolAdapter] | None = None) -> None:
        self._adapters: dict[str, SpecialistToolAdapter] = {}
        for adapter in adapters or []:
            self.register(adapter)

    def register(self, adapter: SpecialistToolAdapter) -> None:
        if adapter.name in self._adapters:
            raise ValueError(f"specialist adapter already registered: {adapter.name}")
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> SpecialistToolAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise KeyError(f"unknown specialist adapter: {name}") from exc

    def describe_all(self) -> list[dict[str, Any]]:
        return [adapter.describe() for adapter in self._adapters.values()]


def build_default_specialist_adapters(
    *,
    tool_executor: Callable[..., ToolResult] = execute_tool,
) -> SpecialistToolAdapterRegistry:
    return SpecialistToolAdapterRegistry(
        [
            WebToolAdapter(tool_executor=tool_executor),
            PlaceholderToolAdapter("crypto", "Crypto"),
            PlaceholderToolAdapter("misc", "Misc"),
        ]
    )


def _first_remote_target(state: ChallengeState) -> str:
    for target in state.get("remote_targets", []):
        if isinstance(target, str) and target.strip():
            return target.strip()
    return ""


def _missing_target_result() -> ToolResult:
    return {
        "tool": "http_get",
        "ok": False,
        "output": "",
        "error": "missing remote target",
        "exit_code": None,
        "metadata": {"url": ""},
    }


def _tool_output(result: ToolResult, *, caller: str) -> dict[str, Any]:
    return {
        "caller": caller,
        "tool": result["tool"],
        "ok": result["ok"],
        "output": result["output"],
        "error": result["error"],
        "exit_code": result["exit_code"],
        "metadata": result.get("metadata", {}),
    }
