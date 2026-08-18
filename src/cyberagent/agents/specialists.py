from typing import Any, Literal

from cyberagent.agents.tool_adapters import (
    SpecialistToolAdapterRegistry,
    build_default_specialist_adapters,
)
from cyberagent.budget import record_tool_budget_usage
from cyberagent.models import ChallengeState, SpecialistResult
from cyberagent.tools import execute_tool
from cyberagent.trace import add_trace_event


def web_agent(
    state: ChallengeState,
    *,
    adapters: SpecialistToolAdapterRegistry | None = None,
) -> SpecialistResult:
    return _run_with_adapter(state, "web_agent", "Web Agent", "web", adapters)


def pwn_agent(state: ChallengeState) -> SpecialistResult:
    return _placeholder_agent(state, "pwn_agent", "Pwn Agent")


def reverse_agent(state: ChallengeState) -> SpecialistResult:
    return _placeholder_agent(state, "reverse_agent", "Reverse Agent")


def crypto_agent(
    state: ChallengeState,
    *,
    adapters: SpecialistToolAdapterRegistry | None = None,
) -> SpecialistResult:
    return _run_with_adapter(state, "crypto_agent", "Crypto Agent", "crypto", adapters)


def misc_agent(
    state: ChallengeState,
    *,
    adapters: SpecialistToolAdapterRegistry | None = None,
) -> SpecialistResult:
    return _run_with_adapter(state, "misc_agent", "Misc Agent", "misc", adapters)


def forensics_agent(
    state: ChallengeState,
    *,
    adapters: SpecialistToolAdapterRegistry | None = None,
) -> SpecialistResult:
    return _run_with_adapter(
        state,
        "forensics_agent",
        "Forensics Agent",
        "forensics",
        adapters,
    )


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
    next_state = record_tool_budget_usage(next_state, result["tool_outputs"])
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
    agent_state = _with_agent_skill_context(state, agent_name)
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
                    "loaded_skills": _loaded_skill_names_for_agent(state, agent_name),
                    "skill_context": agent_state.get("specialist_skill_context", ""),
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


def _run_with_adapter(
    state: ChallengeState,
    agent_name: str,
    display_name: str,
    adapter_name: str,
    adapters: SpecialistToolAdapterRegistry | None,
) -> SpecialistResult:
    if not _is_active(state, agent_name):
        return _skipped(agent_name, f"{display_name} was not selected for this challenge.")

    agent_state = _with_agent_skill_context(state, agent_name)
    registry = adapters or build_default_specialist_adapters(tool_executor=execute_tool)
    try:
        adapter_result = registry.get(adapter_name).execute(agent_state)
    except Exception as exc:  # noqa: BLE001 - adapter failures become structured results
        return _completed(
            agent_name,
            f"{display_name} adapter failed.",
            status="failed",
            error=str(exc),
        )

    return _completed(
        agent_name,
        adapter_result["summary"],
        findings=[
            _finding(
                agent_name,
                f"{display_name} received the challenge.",
                {
                    "title": state.get("title", ""),
                    "predicted_categories": state.get("predicted_categories", []),
                    "active_agents": state.get("active_agents", []),
                    "adapter": adapter_name,
                    "loaded_skills": _loaded_skill_names_for_agent(state, agent_name),
                    "skill_context": agent_state.get("specialist_skill_context", ""),
                },
            ),
            *adapter_result["findings"],
        ],
        candidate_flags=adapter_result["candidate_flags"],
        tool_outputs=adapter_result["tool_outputs"],
        next_actions=adapter_result["next_actions"],
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
    error: str | None = None,
) -> SpecialistResult:
    result: SpecialistResult = {
        "agent": agent,
        "status": status,
        "summary": summary,
        "findings": findings or [],
        "candidate_flags": candidate_flags or [],
        "tool_outputs": tool_outputs or [],
        "next_actions": next_actions or [],
    }
    if error is not None:
        result["error"] = error
    return result


def _with_agent_skill_context(
    state: ChallengeState,
    agent_name: str,
) -> ChallengeState:
    context = state.get("specialist_skill_contexts", {}).get(agent_name, "")
    return {
        **state,
        "specialist_skill_context": context,
    }


def _loaded_skill_names_for_agent(
    state: ChallengeState,
    agent_name: str,
) -> list[str]:
    context = state.get("specialist_skill_contexts", {}).get(agent_name, "")
    if not context:
        return []
    names = []
    for skill in state.get("loaded_skills", []):
        name = skill.get("name", "")
        if name and f"## {name}" in context:
            names.append(name)
    return names


def _finding(agent: str, summary: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "finding",
        "agent": agent,
        "summary": summary,
        "evidence": evidence,
    }
