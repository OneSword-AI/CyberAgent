from typing import Any, Literal

from cyberagent.models import ChallengeState, SpecialistResult
from cyberagent.tools import ToolResult, execute_tool
from cyberagent.trace import add_trace_event


def web_agent(state: ChallengeState) -> SpecialistResult:
    if not _is_active(state, "web_agent"):
        return _skipped("web_agent", "Web Agent was not selected for this challenge.")

    target = _first_remote_target(state)
    result = (
        execute_tool("http_get", {"url": target}, caller="web_agent")
        if target
        else _missing_target_result()
    )
    output = _tool_output(result, caller="web_agent")
    return _completed(
        "web_agent",
        "Web Agent inspected the first remote target.",
        findings=[
            _finding(
                "web_agent",
                "Web Agent received the challenge.",
                {
                    "title": state.get("title", ""),
                    "predicted_categories": state.get("predicted_categories", []),
                    "active_agents": state.get("active_agents", []),
                },
            )
        ],
        tool_outputs=[output],
    )


def pwn_agent(state: ChallengeState) -> SpecialistResult:
    return _placeholder_agent(state, "pwn_agent", "Pwn Agent")


def reverse_agent(state: ChallengeState) -> SpecialistResult:
    return _placeholder_agent(state, "reverse_agent", "Reverse Agent")


def crypto_agent(state: ChallengeState) -> SpecialistResult:
    return _placeholder_agent(state, "crypto_agent", "Crypto Agent")


def misc_agent(state: ChallengeState) -> SpecialistResult:
    return _placeholder_agent(state, "misc_agent", "Misc Agent")


def forensics_agent(state: ChallengeState) -> SpecialistResult:
    return _placeholder_agent(state, "forensics_agent", "Forensics Agent")


def other_agent(state: ChallengeState) -> SpecialistResult:
    return _placeholder_agent(state, "other_agent", "Other Agent")


def apply_specialist_result(
    state: ChallengeState,
    result: SpecialistResult,
) -> ChallengeState:
    """Merge one normalized specialist result into the shared graph state."""
    findings = [*state.get("findings", []), *result["findings"]]
    tool_outputs = [*state.get("tool_outputs", []), *result["tool_outputs"]]
    candidate_flags = list(dict.fromkeys([
        *state.get("candidate_flags", []),
        *result["candidate_flags"],
    ]))
    next_state: ChallengeState = {
        **state,
        "findings": findings,
        "tool_outputs": tool_outputs,
        "candidate_flags": candidate_flags,
        "specialist_results": [
            *state.get("specialist_results", []),
            result,
        ],
    }
    next_state = add_trace_event(
        next_state,
        node=result["agent"],
        event="specialist.receive",
        details={"status": result["status"]},
    )
    for output in result["tool_outputs"]:
        next_state = add_trace_event(
            next_state,
            node=result["agent"],
            event="tool.output",
            details={
                "tool": output.get("tool", ""),
                "ok": output.get("ok", False),
                "exit_code": output.get("exit_code"),
            },
        )
    return add_trace_event(
        next_state,
        node=result["agent"],
        event="specialist.result",
        details={
            "status": result["status"],
            "findings": len(result["findings"]),
            "tool_outputs": len(result["tool_outputs"]),
            "candidate_flags": len(result["candidate_flags"]),
            "next_actions": result["next_actions"],
            **({"error": result["error"]} if "error" in result else {}),
        },
    )


def _placeholder_agent(
    state: ChallengeState,
    agent_name: str,
    display_name: str,
) -> SpecialistResult:
    if not _is_active(state, agent_name):
        return _skipped(agent_name, f"{display_name} was not selected for this challenge.")
    return _completed(
        agent_name,
        f"{display_name} received the challenge; no domain tool adapter is configured yet.",
        findings=[
            _finding(
                agent_name,
                f"{display_name} received the challenge.",
                {
                    "title": state.get("title", ""),
                    "predicted_categories": state.get("predicted_categories", []),
                    "active_agents": state.get("active_agents", []),
                },
            )
        ],
        next_actions=[
            {
                "kind": "tool_adapter",
                "reason": "domain-specific solving tools are not configured",
            }
        ],
    )


def _is_active(state: ChallengeState, agent_name: str) -> bool:
    return agent_name in state.get("active_agents", [])


def _skipped(agent: str, summary: str) -> SpecialistResult:
    return _completed(agent, summary, status="skipped")


def _completed(
    agent: str,
    summary: str,
    *,
    status: Literal["completed", "skipped", "failed"] = "completed",
    findings: list[dict[str, Any]] | None = None,
    candidate_flags: list[str] | None = None,
    tool_outputs: list[dict[str, Any]] | None = None,
    next_actions: list[dict[str, Any]] | None = None,
) -> SpecialistResult:
    return {
        "agent": agent,
        "status": status,
        "summary": summary,
        "findings": findings or [],
        "candidate_flags": candidate_flags or [],
        "tool_outputs": tool_outputs or [],
        "next_actions": next_actions or [],
    }


def _finding(agent: str, summary: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "finding",
        "agent": agent,
        "summary": summary,
        "evidence": evidence,
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
