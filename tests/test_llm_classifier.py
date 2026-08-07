import pytest

from cyberagent.agents.llm_classifier import (
    build_classification_prompt,
    fallback_classify,
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


def test_parse_classification_response_rejects_unknown_category():
    with pytest.raises(ValueError):
        parse_classification_response(
            """
            {
              "predicted_categories": ["Osint"],
              "complexity": "simple",
              "reasoning_summary": "Unknown category.",
              "next_agents": ["misc_agent"]
            }
            """
        )


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
