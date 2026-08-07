import os

import pytest
from dotenv import load_dotenv

from cyberagent.agents.llm_classifier import (
    build_classification_prompt,
    fallback_classify,
    llm_classify_challenge,
    parse_classification_response,
)
from cyberagent.graph import initial_state


def test_build_classification_prompt_includes_challenge_context():
    state = initial_state("1")
    state.update(
        {
            "title": "easy web",
            "description": "A login bypass challenge.",
            "attachments": ["app.zip"],
            "remote_targets": ["http://example.test"],
        }
    )

    prompt = build_classification_prompt(state)

    assert "easy web" in prompt
    assert "A login bypass challenge." in prompt
    assert "app.zip" in prompt
    assert "http://example.test" in prompt
    assert "predicted_categories" in prompt
    assert "next_agents" in prompt


def test_parse_classification_response_accepts_json_code_fence():
    result = parse_classification_response(
        """```json
        {
          "predicted_categories": ["Web"],
          "complexity": "simple",
          "reasoning_summary": "HTTP target and login hint.",
          "next_agents": ["web_agent"]
        }
        ```"""
    )

    assert result["predicted_categories"] == ["Web"]
    assert result["complexity"] == "simple"
    assert result["reasoning_summary"] == "HTTP target and login hint."
    assert result["next_agents"] == ["web_agent"]


def test_parse_classification_response_derives_next_agents_when_missing():
    result = parse_classification_response(
        """
        {
          "predicted_categories": ["Crypto", "Misc"],
          "complexity": "medium",
          "reasoning_summary": "Encoded ciphertext attachment."
        }
        """
    )

    assert result["next_agents"] == ["crypto_agent", "misc_agent"]


def test_parse_classification_response_maps_unknown_category_to_other():
    result = parse_classification_response(
        """
        {
          "predicted_categories": ["Osint"],
          "complexity": "simple",
          "reasoning_summary": "OSINT-style challenge.",
          "next_agents": ["osint_agent"]
        }
        """
    )

    assert result["predicted_categories"] == ["Other"]
    assert result["next_agents"] == ["other_agent"]


def test_fallback_classify_uses_rule_classifier_and_records_error():
    state = initial_state("1")
    state.update(
        {
            "title": "rsa warmup",
            "description": "Recover plaintext from RSA parameters.",
        }
    )

    result = fallback_classify(state, RuntimeError("missing api key"))

    assert result["predicted_categories"] == ["Crypto"]
    assert result["next_agents"] == ["crypto_agent"]
    assert result["complexity"] == "medium"
    assert result["findings"][-1]["agent"] == "llm_classifier"
    assert "missing api key" in result["findings"][-1]["error"]


def test_fallback_classify_uses_other_for_unknown_rule_category():
    state = initial_state("1")
    state.update(
        {
            "title": "guess me",
            "description": "No obvious CTF category hints.",
        }
    )

    result = fallback_classify(state, RuntimeError("invalid llm output"))

    assert result["predicted_categories"] == ["Other"]
    assert result["next_agents"] == ["other_agent"]


@pytest.mark.skipif(
    os.getenv("RUN_LLM_INTEGRATION_TESTS") != "1",
    reason="set RUN_LLM_INTEGRATION_TESTS=1 to call the real LLM API",
)
def test_llm_classify_challenge_with_real_model():
    load_dotenv()
    if not os.getenv("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY is not configured")

    state = initial_state("demo-web")
    state.update(
        {
            "title": "easy login",
            "description": (
                "A web challenge with a login page. Try to bypass authentication "
                "and find the flag."
            ),
            "attachments": [],
            "remote_targets": ["http://example.test"],
            "category_hint": "",
            "flag_format": "flag{...}",
        }
    )

    print("\nLLM integration input:")
    print(f"  model: {os.getenv('OPENAI_MODEL')}")
    print(f"  base_url: {os.getenv('OPENAI_BASE_URL')}")
    print(f"  title: {state.get('title')}")
    print(f"  description: {state.get('description')}")
    print(f"  attachments: {state.get('attachments')}")
    print(f"  remote_targets: {state.get('remote_targets')}")
    print(f"  category_hint: {state.get('category_hint')}")
    print(f"  flag_format: {state.get('flag_format')}")

    result = llm_classify_challenge(state)

    print("\nLLM integration result:")
    print(f"  predicted_categories: {result['predicted_categories']}")
    print(f"  complexity: {result.get('complexity')}")
    print(f"  next_agents: {result['next_agents']}")
    print(f"  reasoning_summary: {result.get('reasoning_summary')}")
    print(f"  last_finding: {result['findings'][-1]}")

    assert result["predicted_categories"]
    assert result["next_agents"]
    assert result.get("complexity") in {"simple", "medium", "complex"}
    assert result.get("reasoning_summary")
    assert result["findings"][-1]["agent"] == "llm_classifier"
    assert "LLM classification failed" not in result["findings"][-1]["summary"]
