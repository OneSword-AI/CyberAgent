from cyberagent.models import ChallengeState
from cyberagent.tools import ToolResult, http_get, record_tool_output


def web_agent(state: ChallengeState) -> ChallengeState:
    state = _run_specialist(state, "web_agent", "Web Agent")
    if "web_agent" not in state.get("active_agents", []):
        return state

    target = _first_remote_target(state)
    result = http_get(target) if target else _missing_target_result()
    return record_tool_output(state, result, caller="web_agent")


def pwn_agent(state: ChallengeState) -> ChallengeState:
    return _run_specialist(state, "pwn_agent", "Pwn Agent")


def reverse_agent(state: ChallengeState) -> ChallengeState:
    return _run_specialist(state, "reverse_agent", "Reverse Agent")


def crypto_agent(state: ChallengeState) -> ChallengeState:
    return _run_specialist(state, "crypto_agent", "Crypto Agent")


def misc_agent(state: ChallengeState) -> ChallengeState:
    return _run_specialist(state, "misc_agent", "Misc Agent")


def forensics_agent(state: ChallengeState) -> ChallengeState:
    return _run_specialist(state, "forensics_agent", "Forensics Agent")


def other_agent(state: ChallengeState) -> ChallengeState:
    return _run_specialist(state, "other_agent", "Other Agent")


def _run_specialist(
    state: ChallengeState,
    agent_name: str,
    display_name: str,
) -> ChallengeState:
    if agent_name not in state.get("active_agents", []):
        return state

    finding = {
        "agent": agent_name,
        "summary": f"{display_name} received the challenge.",
        "evidence": {
            "title": state.get("title", ""),
            "predicted_categories": state.get("predicted_categories", []),
            "active_agents": state.get("active_agents", []),
        },
    }

    return {
        **state,
        "findings": [*state.get("findings", []), finding],
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
