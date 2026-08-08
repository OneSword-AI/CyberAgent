from collections.abc import Callable
from pathlib import Path
from shlex import quote
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


class AttachmentAnalysisAdapter:
    name = "misc"

    def __init__(
        self,
        *,
        tool_executor: Callable[..., ToolResult] = execute_tool,
    ) -> None:
        self._tool_executor = tool_executor

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Analyze downloaded attachments with basic file, strings, and unzip listing commands.",
            "capabilities": ["file", "strings", "unzip_list"],
        }

    def execute(self, state: ChallengeState) -> SpecialistAdapterResult:
        attachments = [
            item
            for item in state.get("downloaded_attachments", [])
            if item.get("ok") and item.get("path")
        ]
        if not attachments:
            return {
                "summary": "Misc Adapter found no downloaded attachments to analyze.",
                "findings": [],
                "candidate_flags": [],
                "tool_outputs": [],
                "next_actions": [
                    {
                        "kind": "attachment",
                        "reason": "no downloaded attachments available",
                    }
                ],
            }

        tool_outputs: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        for attachment in attachments:
            path = str(attachment["path"])
            file_output = self._run_shell(f"file -b {quote(path)}")
            file_output["metadata"] = {
                **file_output.get("metadata", {}),
                "analysis": "file",
                "path": path,
            }
            tool_outputs.append(file_output)

            strings_output = self._run_shell(f"strings -n 4 {quote(path)} | head -200")
            strings_output["metadata"] = {
                **strings_output.get("metadata", {}),
                "analysis": "strings",
                "path": path,
            }
            tool_outputs.append(strings_output)

            if _looks_like_zip(path, file_output.get("output", "")):
                unzip_output = self._run_shell(f"unzip -l {quote(path)}")
                unzip_output["metadata"] = {
                    **unzip_output.get("metadata", {}),
                    "analysis": "unzip_list",
                    "path": path,
                }
                tool_outputs.append(unzip_output)

            findings.append(
                {
                    "kind": "finding",
                    "agent": "misc_agent",
                    "summary": f"Analyzed attachment {Path(path).name}.",
                    "evidence": {
                        "path": path,
                        "file_type": file_output.get("output", "").strip(),
                    },
                }
            )

        return {
            "summary": f"Misc Adapter analyzed {len(attachments)} downloaded attachment(s).",
            "findings": findings,
            "candidate_flags": [],
            "tool_outputs": tool_outputs,
            "next_actions": [],
        }

    def _run_shell(self, command: str) -> dict[str, Any]:
        return _tool_output(
            self._tool_executor("shell", {"command": command}, caller="misc_agent"),
            caller="misc_agent",
        )


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
            AttachmentAnalysisAdapter(tool_executor=tool_executor),
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


def _looks_like_zip(path: str, file_output: str) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix == ".zip" or "zip archive" in file_output.lower()
