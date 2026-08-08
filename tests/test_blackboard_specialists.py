from cyberagent.agents.blackboard_specialists import run_blackboard_specialists
from cyberagent.graph import initial_state
from cyberagent.signals import make_signal


def test_blackboard_specialists_claim_matching_feedback_and_publish_result(monkeypatch):
    calls = []

    def fake_execute_tool(name: str, request: dict, *, caller: str):
        calls.append((name, request["url"], caller))
        return {
            "tool": "http_get",
            "ok": True,
            "output": "flag{blackboard_web}",
            "error": None,
            "exit_code": 0,
            "metadata": {"url": request["url"]},
        }

    monkeypatch.setattr("cyberagent.agents.specialists.execute_tool", fake_execute_tool)
    state = initial_state("bb-web")
    state["remote_targets"] = ["http://web.example.test"]
    task = make_signal(
        type="feedback",
        challenge_id="bb-web",
        source="controller_agent",
        payload={"strategy": "inspect web"},
        provenance="inference",
        recipients=["web_agent"],
    )
    state["signals"] = [task]

    result = run_blackboard_specialists(state)

    assert result["active_agents"] == ["web_agent"]
    assert result["specialist_results"][0]["agent"] == "web_agent"
    assert result["candidate_flags"] == ["flag{blackboard_web}"]
    assert len(calls) == 5
    task_signal = result["signals"][0]
    result_signal = result["signals"][1]
    assert task_signal["status"] == "processed"
    assert task_signal["delivered_to"] == ["web_agent"]
    assert result_signal["type"] == "specialist_result"
    assert result_signal["parent_ids"] == [task["id"]]
    assert result_signal["recipients"] == ["controller_agent"]
    assert result["trace"][-1]["event"] == "blackboard.dispatch"


def test_blackboard_specialists_do_not_duplicate_processed_tasks(monkeypatch):
    calls = []

    def fake_execute_tool(name: str, request: dict, *, caller: str):
        calls.append(request["url"])
        return {
            "tool": "http_get",
            "ok": True,
            "output": "no flag",
            "error": None,
            "exit_code": 0,
            "metadata": {"url": request["url"]},
        }

    monkeypatch.setattr("cyberagent.agents.specialists.execute_tool", fake_execute_tool)
    state = initial_state("bb-web")
    state["remote_targets"] = ["http://web.example.test"]
    state["signals"] = [
        make_signal(
            type="feedback",
            challenge_id="bb-web",
            source="controller_agent",
            payload={"strategy": "inspect web"},
            provenance="inference",
            recipients=["web_agent"],
        )
    ]

    first = run_blackboard_specialists(state)
    second = run_blackboard_specialists(first)

    assert len(calls) == 5
    assert len(second["specialist_results"]) == 1
    assert second["trace"][-1]["details"]["processed"] == 0


def test_blackboard_specialists_match_multiple_recipients_without_fixed_routes():
    state = initial_state("bb-mixed")
    state["signals"] = [
        make_signal(
            type="feedback",
            challenge_id="bb-mixed",
            source="controller_agent",
            payload={"strategy": "try crypto and misc"},
            provenance="inference",
            recipients=["crypto_agent", "misc_agent"],
        )
    ]

    result = run_blackboard_specialists(state)

    assert result["active_agents"] == ["crypto_agent", "misc_agent"]
    assert [item["agent"] for item in result["specialist_results"]] == [
        "crypto_agent",
        "misc_agent",
    ]
    task_signal = result["signals"][0]
    assert task_signal["status"] == "processed"
    assert task_signal["delivered_to"] == ["crypto_agent", "misc_agent"]
