import json

from cyberagent.graph import build_graph, initial_state


def test_graph_fetches_classifies_and_routes_with_fallback(tmp_path, monkeypatch):
    def fake_execute_tool(name: str, request: dict, *, caller: str):
        return {
            "tool": "http_get",
            "ok": True,
            "output": "ok flag{from_web}",
            "error": None,
            "exit_code": 0,
            "metadata": {"url": request["url"]},
        }

    challenge_dir = tmp_path / "challenges"
    challenge_dir.mkdir()
    (challenge_dir / "web01.json").write_text(
        json.dumps(
            {
                "title": "login trail",
                "description": "A web login page leaks SQL errors during authentication.",
                "remote_targets": ["http://web.example.test"],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("CHALLENGE_PROVIDER", "local_json")
    monkeypatch.setenv("CHALLENGE_LOCAL_JSON_DIR", str(challenge_dir))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("cyberagent.agents.specialists.execute_tool", fake_execute_tool)

    result = build_graph().invoke(initial_state("web01"))

    assert result["title"] == "login trail"
    assert result["predicted_categories"] == ["Web"]
    assert result["next_agents"] == ["web_agent"]
    assert result["active_agents"] == ["web_agent"]
    finding_agents = [finding["agent"] for finding in result["findings"]]
    assert "web_agent" in finding_agents
    assert "flag_extractor" in finding_agents
    assert result["tool_outputs"][-1]["caller"] == "web_agent"
    assert result["tool_outputs"][-1]["tool"] == "http_get"
    assert result["tool_outputs"][-1]["ok"] is True
    assert result["candidate_flags"] == ["flag{from_web}"]
    assert result["final_flag"] == "flag{from_web}"
    assert "remote_accepted_flag" not in result
    assert result["submit_results"][-1]["provider"] == "disabled"
    assert result["submit_results"][-1]["submitted"] is False
    assert result["verification_results"][-1]["valid"] is True
    signal_types = [signal["type"] for signal in result["signals"]]
    assert signal_types[:5] == [
        "challenge_input",
        "observation",
        "memory_prior",
        "hypothesis",
        "critic_report",
    ]
    assert len(result["signals"]) >= 5
    signal_statuses = {signal["type"]: signal["status"] for signal in result["signals"]}
    assert signal_statuses["challenge_input"] == "processed"
    assert signal_statuses["observation"] == "processed"
    assert signal_statuses["hypothesis"] == "processed"
    trace_events = [event["event"] for event in result["trace"]]
    assert "challenge.fetch" in trace_events
    assert "llm.fallback" in trace_events
    assert "blackboard.dispatch" in trace_events
    assert "specialist.receive" in trace_events
    assert "tool.output" in trace_events
    assert "flag.extract" in trace_events
    assert "flag.verify" in trace_events
    assert "flag.submit" in trace_events


def test_graph_retries_once_when_no_flag_is_found(tmp_path, monkeypatch):
    calls = []

    def fake_execute_tool(name: str, request: dict, *, caller: str):
        calls.append(request["url"])
        return {
            "tool": "http_get",
            "ok": True,
            "output": "no flag here",
            "error": None,
            "exit_code": 0,
            "metadata": {"url": request["url"]},
        }

    challenge_dir = tmp_path / "challenges"
    challenge_dir.mkdir()
    (challenge_dir / "web02.json").write_text(
        json.dumps(
            {
                "title": "login trail",
                "description": "A web login page leaks SQL errors during authentication.",
                "remote_targets": ["http://web.example.test"],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("CHALLENGE_PROVIDER", "local_json")
    monkeypatch.setenv("CHALLENGE_LOCAL_JSON_DIR", str(challenge_dir))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("cyberagent.agents.specialists.execute_tool", fake_execute_tool)

    result = build_graph().invoke(initial_state("web02"))

    assert len(calls) == 20
    assert calls[:5] == [
        "http://web.example.test",
        "http://web.example.test/robots.txt",
        "http://web.example.test/.git/HEAD",
        "http://web.example.test/admin",
        "http://web.example.test/login",
    ]
    assert result["candidate_flags"] == []
    assert "final_flag" not in result
    assert result["retry_count"] == 1
    assert result["failed_attempts"][-1]["reason"] == "no valid flag accepted"
    trace_events = [event["event"] for event in result["trace"]]
    assert trace_events.count("retry.schedule") == 1
    assert trace_events.count("llm.fallback") == 6
    assert result["failed_attempts"][-1]["plan"]
    assert result["failed_attempts"][-1]["active_agents"] == ["web_agent"]
    assert result["controller_round"] == 3


def test_graph_dispatches_multiple_specialists_with_send(tmp_path, monkeypatch):
    def fake_execute_tool(name: str, request: dict, *, caller: str):
        return {
            "tool": "http_get",
            "ok": True,
            "output": "no flag here",
            "error": None,
            "exit_code": 0,
            "metadata": {"url": request["url"]},
        }

    challenge_dir = tmp_path / "challenges"
    challenge_dir.mkdir()
    (challenge_dir / "mixed01.json").write_text(
        json.dumps(
            {
                "title": "web crypto mix",
                "description": "web http service with crypto rsa notes",
                "remote_targets": ["http://web.example.test"],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("CHALLENGE_PROVIDER", "local_json")
    monkeypatch.setenv("CHALLENGE_LOCAL_JSON_DIR", str(challenge_dir))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("cyberagent.agents.specialists.execute_tool", fake_execute_tool)

    state = initial_state("mixed01")
    state["max_retries"] = 0
    result = build_graph().invoke(state)

    assert result["active_agents"] == ["web_agent", "crypto_agent"]
    finding_agents = [finding["agent"] for finding in result["findings"]]
    assert "web_agent" in finding_agents
    assert "crypto_agent" in finding_agents
    signal_types = [signal["type"] for signal in result["signals"]]
    assert signal_types.count("specialist_result") == 4
    assert result["controller_round"] == 3
