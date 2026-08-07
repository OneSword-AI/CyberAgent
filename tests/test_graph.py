import json

from cyberagent.graph import build_graph, initial_state


def test_graph_fetches_classifies_and_routes_with_fallback(tmp_path, monkeypatch):
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

    result = build_graph().invoke(initial_state("web01"))

    assert result["title"] == "login trail"
    assert result["predicted_categories"] == ["Web"]
    assert result["next_agents"] == ["web_agent"]
    assert result["active_agents"] == ["web_agent"]
    assert result["findings"][-1]["agent"] == "web_agent"
    assert result["tool_outputs"][-1]["caller"] == "web_agent"
    assert result["tool_outputs"][-1]["tool"] == "web_probe"
    assert result["tool_outputs"][-1]["ok"] is True
