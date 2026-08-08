import re
from collections.abc import Callable
from pathlib import Path
from shlex import quote
from typing import Any, Protocol, TypedDict, runtime_checkable
from urllib.parse import urljoin

from cyberagent.budget import (
    budget_allows_tool,
    budget_denied_tool_result,
    budget_exhaustion_reason,
)
from cyberagent.flag import extract_flags, merge_candidate_flags
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
    probe_paths = ("/robots.txt", "/.git/HEAD", "/admin", "/login")

    def __init__(
        self,
        *,
        tool_executor: Callable[..., ToolResult] = execute_tool,
    ) -> None:
        self._tool_executor = tool_executor

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Perform bounded HTTP probing, path attempts, response flag extraction, and simple form/parameter discovery.",
            "capabilities": ["http_get", "path_probe", "flag_extract", "form_detect", "parameter_detect"],
        }

    def execute(self, state: ChallengeState) -> SpecialistAdapterResult:
        target = _first_remote_target(state)
        if not target:
            output = _tool_output(_missing_target_result(), caller="web_agent")
            return {
                "summary": "Web Adapter could not run because no remote target is configured.",
                "findings": [],
                "candidate_flags": [],
                "tool_outputs": [output],
                "next_actions": [{"kind": "remote_target", "reason": "missing remote target"}],
            }

        urls = _web_probe_urls(target, self.probe_paths)
        budget_state = state
        tool_outputs = []
        for url in urls:
            output = self._http_get(url, budget_state)
            tool_outputs.append(output)
            budget_state = _count_local_budget_use(budget_state, output)
        candidate_flags: list[str] = []
        findings: list[dict[str, Any]] = []
        forms: list[dict[str, Any]] = []
        parameters: list[dict[str, Any]] = []

        for output in tool_outputs:
            body = str(output.get("output", ""))
            candidate_flags = merge_candidate_flags(
                candidate_flags,
                extract_flags(body, state.get("flag_format")),
            )
            url = str(output.get("metadata", {}).get("url", ""))
            forms.extend(_detect_forms(body, url))
            parameters.extend(_detect_parameters(body, url))

        if forms:
            findings.append(
                _adapter_finding(
                    "Detected simple HTML form(s).",
                    {"forms": forms},
                )
            )
        if parameters:
            findings.append(
                _adapter_finding(
                    "Detected candidate URL parameter(s).",
                    {"parameters": parameters},
                )
            )

        return {
            "summary": f"Web Adapter probed {len(urls)} URL(s).",
            "findings": findings,
            "candidate_flags": candidate_flags,
            "tool_outputs": tool_outputs,
            "next_actions": [],
        }

    def _http_get(self, url: str, state: ChallengeState) -> dict[str, Any]:
        if not budget_allows_tool(state, "http_get"):
            return _tool_output(
                budget_denied_tool_result("http_get", budget_exhaustion_reason(state, "http_get")),
                caller="web_agent",
            )
        return _tool_output(
            self._tool_executor("http_get", {"url": url}, caller="web_agent"),
            caller="web_agent",
        )


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
        budget_state = state
        for attachment in attachments:
            path = str(attachment["path"])
            file_output = self._run_shell(f"file -b {quote(path)}", budget_state)
            budget_state = _count_local_budget_use(budget_state, file_output)
            file_output["metadata"] = {
                **file_output.get("metadata", {}),
                "analysis": "file",
                "path": path,
            }
            tool_outputs.append(file_output)

            strings_output = self._run_shell(f"strings -n 4 {quote(path)} | head -200", budget_state)
            budget_state = _count_local_budget_use(budget_state, strings_output)
            strings_output["metadata"] = {
                **strings_output.get("metadata", {}),
                "analysis": "strings",
                "path": path,
            }
            tool_outputs.append(strings_output)

            if _looks_like_zip(path, file_output.get("output", "")):
                unzip_output = self._run_shell(f"unzip -l {quote(path)}", budget_state)
                budget_state = _count_local_budget_use(budget_state, unzip_output)
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

    def _run_shell(self, command: str, state: ChallengeState) -> dict[str, Any]:
        if not budget_allows_tool(state, "shell"):
            return _tool_output(
                budget_denied_tool_result("shell", budget_exhaustion_reason(state, "shell")),
                caller="misc_agent",
            )
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


def _count_local_budget_use(state: ChallengeState, output: dict[str, Any]) -> ChallengeState:
    usage = dict(state.get("budget_usage", {}))
    tool = output.get("tool", "")
    if output.get("metadata", {}).get("budget_denied"):
        return state
    usage["tool_calls"] = usage.get("tool_calls", 0) + 1
    if tool.startswith("http_"):
        usage["http_requests"] = usage.get("http_requests", 0) + 1
    if tool == "shell":
        usage["shell_commands"] = usage.get("shell_commands", 0) + 1
    return {**state, "budget_usage": usage}


def _web_probe_urls(target: str, paths: tuple[str, ...]) -> list[str]:
    urls = [target]
    for path in paths:
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        if url not in urls:
            urls.append(url)
    return urls


def _detect_forms(body: str, page_url: str) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    for match in re.finditer(r"<form\b(?P<attrs>[^>]*)>", body, flags=re.IGNORECASE):
        attrs = match.group("attrs")
        forms.append(
            {
                "page": page_url,
                "method": _html_attr(attrs, "method") or "get",
                "action": _html_attr(attrs, "action") or page_url,
                "inputs": _nearby_inputs(body, match.end()),
            }
        )
    return forms


def _nearby_inputs(body: str, start: int) -> list[str]:
    end = body.find("</form>", start)
    fragment = body[start : end if end != -1 else start + 2000]
    names = [
        match.group(1)
        for match in re.finditer(
            r"<input\b[^>]*\bname=[\"']?([^\"'\s>]+)",
            fragment,
            flags=re.IGNORECASE,
        )
    ]
    return list(dict.fromkeys(names))


def _detect_parameters(body: str, page_url: str) -> list[dict[str, Any]]:
    parameters: list[dict[str, Any]] = []
    for href in re.findall(r"\bhref=[\"']([^\"']+\?[^\"']+)[\"']", body, flags=re.IGNORECASE):
        query = href.split("?", 1)[1].split("#", 1)[0]
        names = [
            item.split("=", 1)[0]
            for item in query.split("&")
            if item and item.split("=", 1)[0]
        ]
        if names:
            parameters.append(
                {
                    "page": page_url,
                    "href": href,
                    "names": list(dict.fromkeys(names)),
                }
            )
    return parameters


def _html_attr(attrs: str, name: str) -> str:
    match = re.search(
        rf"\b{name}=[\"']?([^\"'\s>]+)",
        attrs,
        flags=re.IGNORECASE,
    )
    return match.group(1).lower() if match else ""


def _adapter_finding(summary: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "finding",
        "agent": "web_agent",
        "summary": summary,
        "evidence": evidence,
    }
