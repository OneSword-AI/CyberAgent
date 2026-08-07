import json

from cyberagent.graph import build_graph, initial_state


def test_graph_fetches_classifies_and_routes_with_fallback(tmp_path, monkeypatch):
    def fake_http_get(url: str):
        return {
            "tool": "http_get",
            "ok": True,
            "output": "ok flag{from_web}",
            "error": None,
            "exit_code": 0,
            "metadata": {"url": url},
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
    monkeypatch.setattr("cyberagent.agents.specialists.http_get", fake_http_get)

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
    trace_events = [event["event"] for event in result["trace"]]
    assert "challenge.fetch" in trace_events
    assert "llm.fallback" in trace_events
    assert "agent.route" in trace_events
    assert "specialist.receive" in trace_events
    assert "tool.output" in trace_events
    assert "flag.extract" in trace_events
