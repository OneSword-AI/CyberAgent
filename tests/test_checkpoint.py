from cyberagent.checkpoint import load_state, save_state
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
