import os
from typing import TypedDict

import pytest
from dotenv import load_dotenv

from cyberagent.agents.llm_classifier import llm_classify_challenge
from cyberagent.graph import initial_state


class ChallengeCase(TypedDict):
    challenge_id: str
    title: str
    description: str
    attachments: list[str]
    remote_targets: list[str]
    expected_categories: set[str]


CHALLENGE_CASES: list[ChallengeCase] = [
    {
        "challenge_id": "analysis-web-zh",
        "title": "旧门牌",
        "description": (
            "管理员说访客只能从正门登记，但门卫记录里总有一行空白。"
            "页面看起来只是普通查询，偶尔会把不该出现的房间号也带出来。"
        ),
        "attachments": [],
        "remote_targets": ["http://challenge.example.test"],
        "expected_categories": {"Web"},
    },
    {
        "challenge_id": "analysis-pwn-zh",
        "title": "回声筒",
        "description": (
            "服务会原样复述你说的话，只是话太长时会变得健忘。"
            "管理员留下了运行程序和远程地址，说真正的秘密藏在进程另一侧。"
        ),
        "attachments": ["echo_server"],
        "remote_targets": ["nc pwn.example.test 31337"],
        "expected_categories": {"Pwn"},
    },
    {
        "challenge_id": "analysis-reverse-zh",
        "title": "验票员",
        "description": (
            "一个小工具只认某种通行短语。它不会联网，也不给提示，"
            "只是在输入不合适时很快关门。找出能通过检票的那句话。"
        ),
        "attachments": ["checker.bin"],
        "remote_targets": [],
        "expected_categories": {"Reverse"},
    },
    {
        "challenge_id": "analysis-crypto-zh",
        "title": "旧账本",
        "description": (
            "账本里只有三列数字和一段看似随机的长串。出题人说钥匙没有丢，"
            "只是被重复使用得太勤，耐心一点就能还原原文。"
        ),
        "attachments": ["ledger.txt"],
        "remote_targets": [],
        "expected_categories": {"Crypto"},
    },
    {
        "challenge_id": "analysis-forensics-zh",
        "title": "凌晨三点的访客",
        "description": (
            "值班同学只保存了一份现场记录。里面有人来过、下载过东西，"
            "又把痕迹藏在正常会话之间。请从记录里还原那段被带走的信息。"
        ),
        "attachments": ["capture.pcapng"],
        "remote_targets": [],
        "expected_categories": {"Forensics"},
    },
    {
        "challenge_id": "analysis-other-zh",
        "title": "第七盏灯",
        "description": (
            "桌上有七盏灯、三张便签和一串没有明显格式的回答。"
            "规则不在文件里，也不在网络里，需要先猜出出题人使用的映射方式。"
        ),
        "attachments": [],
        "remote_targets": [],
        "expected_categories": {"Misc", "Other"},
    },
]


@pytest.mark.skipif(
    os.getenv("RUN_LLM_ANALYSIS_TESTS") != "1",
    reason="set RUN_LLM_ANALYSIS_TESTS=1 to evaluate the real LLM on challenge analysis",
)
@pytest.mark.parametrize("case", CHALLENGE_CASES, ids=[case["challenge_id"] for case in CHALLENGE_CASES])
def test_llm_analyzes_chinese_challenge_descriptions(case: ChallengeCase):
    load_dotenv()
    if not os.getenv("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY is not configured")

    state = initial_state(case["challenge_id"])
    state.update(
        {
            "title": case["title"],
            "description": case["description"],
            "attachments": case["attachments"],
            "remote_targets": case["remote_targets"],
            "category_hint": "",
            "flag_format": "flag{...}",
        }
    )

    result = llm_classify_challenge(state)
    actual_categories = set(result["predicted_categories"])

    print("\nLLM challenge analysis comparison:")
    print(f"  case: {case['challenge_id']}")
    print(f"  model: {os.getenv('OPENAI_MODEL')}")
    print(f"  base_url: {os.getenv('OPENAI_BASE_URL')}")
    print(f"  title: {case['title']}")
    print(f"  description: {case['description']}")
    print(f"  attachments: {case['attachments']}")
    print(f"  remote_targets: {case['remote_targets']}")
    print(f"  expected_categories: {sorted(case['expected_categories'])}")
    print(f"  actual_categories: {result['predicted_categories']}")
    print(f"  complexity: {result.get('complexity')}")
    print(f"  next_agents: {result['next_agents']}")
    print(f"  reasoning_summary: {result.get('reasoning_summary')}")
    print(f"  matched: {bool(actual_categories & case['expected_categories'])}")

    assert result["findings"][-1]["agent"] == "llm_classifier"
    assert "LLM classification failed" not in result["findings"][-1]["summary"]
    assert actual_categories & case["expected_categories"]
