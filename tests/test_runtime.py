from cyberagent import runtime


class FakeGraph:
    def invoke(self, state):
        return {**state, "title": "from runtime"}


def test_run_challenge_builds_initial_state_and_invokes_graph(monkeypatch):
    monkeypatch.setattr(runtime, "load_dotenv", lambda: None)
    monkeypatch.setattr(runtime, "build_graph", lambda: FakeGraph())

    result = runtime.run_challenge("runtime01")

    assert result["challenge_id"] == "runtime01"
    assert result["title"] == "from runtime"
    assert result["candidate_flags"] == []


def test_run_challenge_can_skip_env_loading(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "load_dotenv", lambda: calls.append("load"))
    monkeypatch.setattr(runtime, "build_graph", lambda: FakeGraph())

    runtime.run_challenge("runtime01", load_env=False)

    assert calls == []
