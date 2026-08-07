import json
import re
from typing import Any, TypedDict

from cyberagent.agents.classifier import KNOWN_CATEGORIES, classify_challenge
from cyberagent.llm import get_llm
from cyberagent.models import ChallengeState


KNOWN_AGENTS = {
    "Web": "web_agent",
    "Pwn": "pwn_agent",
    "Reverse": "reverse_agent",
    "Crypto": "crypto_agent",
    "Misc": "misc_agent",
    "Forensics": "forensics_agent",
}
KNOWN_COMPLEXITIES = ("simple", "medium", "complex")


class ClassificationResult(TypedDict):
    predicted_categories: list[str]
    complexity: str
    reasoning_summary: str
    next_agents: list[str]


def llm_classify_challenge(state: ChallengeState) -> ChallengeState:
    """Classify a CTF challenge with an LLM, falling back to rules on failure."""
    try:
        llm = get_llm()
        response = llm.invoke(build_classification_prompt(state))
        result = parse_classification_response(str(response.content))
    except Exception as exc:
        return fallback_classify(state, exc)

    finding = {
        "agent": "llm_classifier",
        "summary": result["reasoning_summary"],
        "evidence": {
            "predicted_categories": result["predicted_categories"],
            "complexity": result["complexity"],
            "next_agents": result["next_agents"],
        },
    }

    return {
        **state,
        "predicted_categories": result["predicted_categories"],
        "complexity": result["complexity"],
        "reasoning_summary": result["reasoning_summary"],
        "next_agents": result["next_agents"],
        "findings": [*state.get("findings", []), finding],
    }


def build_classification_prompt(state: ChallengeState) -> str:
    return f"""
你是 CyberAgent 的 CTF 题目分类节点。

请根据题目信息判断题目方向、复杂度和下一步应调度的专科 Agent。

允许的题目方向只能是：
{", ".join(KNOWN_CATEGORIES)}

允许的复杂度只能是：
{", ".join(KNOWN_COMPLEXITIES)}

允许的 next_agents 只能是：
{", ".join(KNOWN_AGENTS.values())}

题目标题：
{state.get("title", "")}

题目描述：
{state.get("description", "")}

分类提示：
{state.get("category_hint", "")}

Flag 格式：
{state.get("flag_format", "")}

附件：
{json.dumps(state.get("attachments", []), ensure_ascii=False)}

远程目标：
{json.dumps(state.get("remote_targets", []), ensure_ascii=False)}

只返回 JSON，不要返回 Markdown，不要解释：
{{
  "predicted_categories": ["Web"],
  "complexity": "simple",
  "reasoning_summary": "一句话说明判断依据",
  "next_agents": ["web_agent"]
}}
""".strip()


def parse_classification_response(content: str) -> ClassificationResult:
    data = json.loads(_strip_json_code_fence(content))
    if not isinstance(data, dict):
        raise ValueError("classification response must be a JSON object")
    return validate_classification_result(data)


def validate_classification_result(data: dict[str, Any]) -> ClassificationResult:
    categories = _validated_str_list(
        data,
        "predicted_categories",
        allowed=set(KNOWN_CATEGORIES),
        required=True,
    )
    complexity = _validated_str(
        data,
        "complexity",
        allowed=set(KNOWN_COMPLEXITIES),
        default="medium",
    )
    next_agents = _validated_str_list(
        data,
        "next_agents",
        allowed=set(KNOWN_AGENTS.values()),
        required=False,
    )

    if not next_agents:
        next_agents = [KNOWN_AGENTS[category] for category in categories]

    reasoning_summary = _validated_str(data, "reasoning_summary", default="")
    if not reasoning_summary:
        reasoning_summary = f"LLM predicted category: {', '.join(categories)}"

    return {
        "predicted_categories": categories,
        "complexity": complexity,
        "reasoning_summary": reasoning_summary,
        "next_agents": next_agents,
    }


def fallback_classify(state: ChallengeState, error: Exception) -> ChallengeState:
    fallback_state = classify_challenge(state)
    categories = fallback_state.get("predicted_categories", [])
    next_agents = [KNOWN_AGENTS[category] for category in categories if category in KNOWN_AGENTS]

    finding = {
        "agent": "llm_classifier",
        "summary": "LLM classification failed; used rule-based fallback.",
        "error": str(error),
    }

    return {
        **fallback_state,
        "complexity": fallback_state.get("complexity", "medium"),
        "reasoning_summary": fallback_state.get(
            "reasoning_summary",
            "LLM classification failed; used rule-based fallback.",
        ),
        "next_agents": next_agents,
        "findings": [*fallback_state.get("findings", []), finding],
    }


def _strip_json_code_fence(content: str) -> str:
    content = content.strip()
    match = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", content, flags=re.DOTALL)
    return match.group(1).strip() if match else content


def _validated_str_list(
    data: dict[str, Any],
    key: str,
    *,
    allowed: set[str],
    required: bool,
) -> list[str]:
    value = data.get(key)
    if value is None and not required:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list")

    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{key} must contain only strings")
        item = item.strip()
        if item not in allowed:
            raise ValueError(f"unsupported {key} value: {item}")
        result.append(item)

    result = list(dict.fromkeys(result))
    if required and not result:
        raise ValueError(f"{key} must not be empty")
    return result


def _validated_str(
    data: dict[str, Any],
    key: str,
    *,
    allowed: set[str] | None = None,
    default: str,
) -> str:
    value = data.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")

    value = value.strip()
    if not value:
        return default
    if allowed and value not in allowed:
        raise ValueError(f"unsupported {key} value: {value}")
    return value
