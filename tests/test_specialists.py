from cyberagent.agents.specialists import (
    crypto_agent,
    forensics_agent,
    misc_agent,
    other_agent,
    pwn_agent,
    reverse_agent,
    web_agent,
)
from cyberagent.graph import initial_state


def test_specialist_adds_finding_when_active(monkeypatch):
    def fake_execute_tool(name: str, request: dict, *, caller: str):
        assert name == "http_get"
        assert request["url"] == "http://example.test"
        assert caller == "web_agent"
        return {
            "tool": "http_get",
            "ok": True,
            "output": "ok",
            "error": None,
            "exit_code": 0,
            "metadata": {"url": request["url"]},
        }

    state = initial_state("1")
    state.update(
        {
            "title": "easy web",
            "predicted_categories": ["Web"],
            "active_agents": ["web_agent"],
            "remote_targets": ["http://example.test"],
        }
    )

    monkeypatch.setattr("cyberagent.agents.specialists.execute_tool", fake_execute_tool)
    result = web_agent(state)

    assert result["agent"] == "web_agent"
    assert result["status"] == "completed"
    assert result["findings"][-1]["agent"] == "web_agent"
    assert result["findings"][-1]["summary"] == "Web Agent received the challenge."
    assert result["tool_outputs"][-1]["caller"] == "web_agent"
    assert result["tool_outputs"][-1]["tool"] == "http_get"
    assert result["tool_outputs"][-1]["ok"] is True


def test_specialist_returns_state_when_inactive():
    state = initial_state("1")
    state.update(
        {
            "title": "rsa warmup",
            "predicted_categories": ["Crypto"],
            "active_agents": ["crypto_agent"],
        }
    )

    result = web_agent(state)

    assert result["agent"] == "web_agent"
    assert result["status"] == "skipped"
    assert result["findings"] == []


def test_all_specialist_nodes_can_receive_challenge(monkeypatch):
    def fake_execute_tool(name: str, request: dict, *, caller: str):
        return {
            "tool": "http_get",
            "ok": True,
            "output": "ok",
            "error": None,
            "exit_code": 0,
            "metadata": {"url": request["url"]},
        }

    monkeypatch.setattr("cyberagent.agents.specialists.execute_tool", fake_execute_tool)
    specialists = [
        ("web_agent", web_agent),
        ("pwn_agent", pwn_agent),
        ("reverse_agent", reverse_agent),
        ("crypto_agent", crypto_agent),
        ("misc_agent", misc_agent),
        ("forensics_agent", forensics_agent),
        ("other_agent", other_agent),
    ]

    for agent_name, agent_func in specialists:
        state = initial_state(agent_name)
        state["active_agents"] = [agent_name]
        state["remote_targets"] = ["http://example.test"]

        result = agent_func(state)

        assert result["agent"] == agent_name
        assert result["status"] == "completed"
        assert result["findings"][-1]["agent"] == agent_name


def test_web_agent_records_missing_target_tool_error():
    state = initial_state("1")
    state["active_agents"] = ["web_agent"]

    result = web_agent(state)

    assert result["agent"] == "web_agent"
    assert result["tool_outputs"][-1]["tool"] == "http_get"
    assert result["tool_outputs"][-1]["ok"] is False
    assert result["tool_outputs"][-1]["error"] == "missing remote target"
