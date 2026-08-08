from cyberagent.checkpoint import load_state, save_run_outputs, save_state
from cyberagent.graph import initial_state


def test_save_state_writes_json(tmp_path):
    state = initial_state("check01")
    state["title"] = "checkpoint test"

    path = save_state(state, tmp_path)

    assert path == tmp_path / "check01" / "state.json"
    assert path.exists()
    assert "checkpoint test" in path.read_text(encoding="utf-8")


def test_load_state_reads_existing_state(tmp_path):
    state = initial_state("check01")
    state["candidate_flags"] = ["flag{saved}"]
    save_state(state, tmp_path)

    loaded = load_state("check01", tmp_path)

    assert loaded is not None
    assert loaded["challenge_id"] == "check01"
    assert loaded["candidate_flags"] == ["flag{saved}"]


def test_load_state_returns_none_for_missing_state(tmp_path):
    assert load_state("missing", tmp_path) is None


def test_save_run_outputs_writes_report_flag_log_and_state(tmp_path):
    state = initial_state("run01")
    state.update(
        {
            "title": "run output test",
            "candidate_flags": ["flag{candidate}"],
            "final_flag": "flag{candidate}",
            "trace": [
                {
                    "ts": 1.0,
                    "node": "controller_agent",
                    "event": "controller.plan",
                    "details": {"next_agents": ["web_agent"]},
                }
            ],
        }
    )

    paths = save_run_outputs(state, tmp_path)

    assert paths["state"] == tmp_path / "run01" / "state.json"
    assert paths["report"] == tmp_path / "run01" / "report.md"
    assert paths["flag"] == tmp_path / "run01" / "flag.txt"
    assert paths["log"] == tmp_path / "run01" / "run.log"
    assert "run output test" in paths["report"].read_text(encoding="utf-8")
    assert paths["flag"].read_text(encoding="utf-8") == "flag{candidate}\n"
    assert "controller_agent\tcontroller.plan" in paths["log"].read_text(encoding="utf-8")
