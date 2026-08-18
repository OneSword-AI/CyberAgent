import pytest

from cyberagent.agents.controller import (
    build_controller_prompt,
    fallback_controller_plan,
    parse_controller_response,
    run_controller_agent,
)
from cyberagent.graph import initial_state


def _response(payload: dict):
    class Response:
        content = __import__("json").dumps(payload)

    return Response()


def test_controller_prompt_includes_context():
    state = initial_state("controller01")
    state.update({"title": "web login", "description": "SQL errors", "remote_targets": ["http://x"]})
    prompt = build_controller_prompt(state)
    assert "web login" in prompt
    assert "goal" in prompt
    assert "stop_condition" in prompt


def test_controller_prompt_includes_skill_context():
    state = initial_state("controller-skill")
    state["skill_context"] = "## ctf-web\nUse bounded active interaction."
    prompt = build_controller_prompt(state)

    assert "已加载的 CTF Skill 指令" in prompt
    assert "Use bounded active interaction." in prompt


def test_parse_controller_response_validates_all_fields():
    result = parse_controller_response(
        '{"goal":"get flag","strategy":"probe","predicted_categories":["Web"],'
        '"complexity":"simple","next_agents":["web_agent"],"rationale":"http",'
        '"stop_condition":"valid flag"}'
    )
    assert result["next_agents"] == ["web_agent"]
    assert result["complexity"] == "simple"


def test_parse_controller_response_rejects_invalid_result():
    with pytest.raises(ValueError):
        parse_controller_response('{"goal":"x","strategy":"y"}')


def test_controller_uses_mock_llm(monkeypatch):
    payload = {
        "goal": "get flag", "strategy": "inspect web", "predicted_categories": ["Web"],
        "complexity": "medium", "next_agents": ["web_agent"], "rationale": "http target",
        "stop_condition": "verified flag",
    }

    class FakeLLM:
        def invoke(self, prompt):
            return _response(payload)

    monkeypatch.setattr("cyberagent.agents.controller.get_llm", lambda: FakeLLM())
    result = run_controller_agent(initial_state("controller02"))
    assert result["plan"] == "inspect web"
    assert result["controller_decisions"]["goal"] == "get flag"
    assert result["signals"][-1]["type"] == "feedback"
    assert result["trace"][-1]["event"] == "controller.plan"


def test_controller_falls_back_to_rule_classifier(monkeypatch):
    def fail_llm():
        raise RuntimeError("missing api key")

    monkeypatch.setattr("cyberagent.agents.controller.get_llm", fail_llm)
    state = initial_state("controller03")
    state.update({"title": "rsa", "description": "crypto ciphertext"})
    result = run_controller_agent(state)
    assert result["predicted_categories"] == ["Crypto"]
    assert result["next_agents"] == ["crypto_agent"]
    assert result["trace"][-1]["event"] == "llm.fallback"
    assert "missing api key" in result["findings"][-1]["error"]
    assert fallback_controller_plan is not None
