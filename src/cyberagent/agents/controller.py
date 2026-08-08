import json
import re
from typing import Any, TypedDict

from cyberagent.agents.classifier import classify_challenge
from cyberagent.agents.constants import (
    CATEGORY_TO_AGENT,
    KNOWN_AGENT_NAMES,
    KNOWN_CATEGORIES,
    KNOWN_COMPLEXITIES,
)
from cyberagent.evidence import add_finding
from cyberagent.llm import get_llm
from cyberagent.models import ChallengeState
from cyberagent.signals import make_signal
from cyberagent.trace import add_trace_event


class ControllerPlan(TypedDict):
    goal: str
    strategy: str
    predicted_categories: list[str]
    complexity: str
    next_agents: list[str]
    rationale: str
    stop_condition: str


def run_controller_agent(state: ChallengeState) -> ChallengeState:
    """Produce and validate a solving plan, using rules when the LLM fails."""
    try:
        response = get_llm().invoke(build_controller_prompt(state))
        plan = parse_controller_response(str(response.content))
    except Exception as exc:
        return fallback_controller_plan(state, exc)

    return _apply_plan(state, plan, event="controller.plan", error=None)


def build_controller_prompt(state: ChallengeState) -> str:
    return f"""
你是 CyberAgent 的控制器节点。请根据题目信息和已有信号制定可执行的 CTF 解题计划。
只返回 JSON，不要返回 Markdown 或解释。所有字段都必须存在：goal、strategy、predicted_categories、complexity、next_agents、rationale、stop_condition。
题目标题：{state.get("title", "")}
题目描述：{state.get("description", "")}
分类提示：{state.get("category_hint", "")}
附件：{json.dumps(state.get("attachments", []), ensure_ascii=False)}
远程目标：{json.dumps(state.get("remote_targets", []), ensure_ascii=False)}
已有计划：{state.get("plan", "")}
已有活动 Agent：{json.dumps(state.get("active_agents", []), ensure_ascii=False)}
已有信号：{json.dumps(state.get("signals", []), ensure_ascii=False)}
允许的分类：{", ".join(KNOWN_CATEGORIES)}
允许的复杂度：{", ".join(KNOWN_COMPLEXITIES)}
允许的 next_agents：{", ".join(KNOWN_AGENT_NAMES)}
JSON 示例：
{{
  "goal": "获取并验证 flag",
  "strategy": "先分析 Web 入口，再提取候选 flag",
  "predicted_categories": ["Web"],
  "complexity": "medium",
  "next_agents": ["web_agent"],
  "rationale": "题目包含 HTTP 登录入口",
  "stop_condition": "发现通过验证的 flag"
}}
""".strip()


def parse_controller_response(content: str) -> ControllerPlan:
    data = json.loads(_strip_json_code_fence(content))
    if not isinstance(data, dict):
        raise ValueError("controller response must be a JSON object")
    required = ("goal", "strategy", "predicted_categories", "complexity", "next_agents", "rationale", "stop_condition")
    missing = [key for key in required if key not in data]
    if missing:
        raise ValueError(f"missing controller fields: {', '.join(missing)}")
    for key in ("goal", "strategy", "rationale", "stop_condition"):
        if not isinstance(data[key], str) or not data[key].strip():
            raise ValueError(f"{key} must be a non-empty string")
    categories = _string_list(data["predicted_categories"], "predicted_categories")
    if not categories or any(value not in KNOWN_CATEGORIES for value in categories):
        raise ValueError("predicted_categories contains unsupported values")
    complexity = data["complexity"]
    if complexity not in KNOWN_COMPLEXITIES:
        raise ValueError("unsupported complexity")
    next_agents = _string_list(data["next_agents"], "next_agents")
    if not next_agents or any(value not in KNOWN_AGENT_NAMES for value in next_agents):
        raise ValueError("next_agents contains unsupported values")
    return {
        "goal": data["goal"].strip(),
        "strategy": data["strategy"].strip(),
        "predicted_categories": list(dict.fromkeys(categories)),
        "complexity": complexity,
        "next_agents": list(dict.fromkeys(next_agents)),
        "rationale": data["rationale"].strip(),
        "stop_condition": data["stop_condition"].strip(),
    }


def fallback_controller_plan(state: ChallengeState, error: Exception) -> ChallengeState:
    classified = classify_challenge(state)
    categories = classified.get("predicted_categories", ["Other"])
    next_agents = [CATEGORY_TO_AGENT.get(category, "other_agent") for category in categories]
    plan: ControllerPlan = {
        "goal": "获取并验证 flag",
        "strategy": "使用规则分类结果调度专科 Agent",
        "predicted_categories": categories,
        "complexity": "medium",
        "next_agents": next_agents,
        "rationale": "控制器不可用，使用现有规则分类回退",
        "stop_condition": "发现通过验证的 flag 或达到重试上限",
    }
    return _apply_plan(state, plan, event="llm.fallback", error=error)


def _apply_plan(state: ChallengeState, plan: ControllerPlan, *, event: str, error: Exception | None) -> ChallengeState:
    decisions = dict(plan)
    next_state: ChallengeState = {
        **state,
        "controller_round": state.get("controller_round", 0) + 1,
        "plan": plan["strategy"],
        "plan_rationale": plan["rationale"],
        "controller_decisions": decisions,
        "predicted_categories": plan["predicted_categories"],
        "complexity": plan["complexity"],
        "next_agents": plan["next_agents"],
        "stop_condition": plan["stop_condition"],
    }
    feedback = make_signal(
        type="feedback",
        challenge_id=state.get("challenge_id", ""),
        source="controller_agent",
        payload={"goal": plan["goal"], "strategy": plan["strategy"], "next_agents": plan["next_agents"]},
        provenance="inference",
        recipients=plan["next_agents"],
    )
    next_state["signals"] = [*state.get("signals", []), feedback]
    next_state = add_trace_event(next_state, node="controller_agent", event=event, details=decisions | ({"error": str(error)} if error else {}))
    return add_finding(
        next_state,
        agent="controller_agent",
        summary=plan["rationale"],
        evidence=decisions,
        error=str(error) if error else None,
    )


def _string_list(value: Any, key: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{key} must be a non-empty list of strings")
    return [item.strip() for item in value]


def _strip_json_code_fence(content: str) -> str:
    content = content.strip()
    match = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", content, flags=re.DOTALL)
    return match.group(1).strip() if match else content
