from cyberagent.agents.flag_submitter import submit_flag
from cyberagent.graph import initial_state


class FakeSubmitProvider:
    name = "fake"

    def __init__(self, *, accepted: bool | None = True) -> None:
        self.accepted = accepted
        self.calls: list[tuple[str, str]] = []

    def submit(self, challenge_id: str, flag: str) -> dict:
        self.calls.append((challenge_id, flag))
        return {
            "submitted": True,
            "accepted": self.accepted,
            "status": "accepted" if self.accepted else "rejected",
            "message": "ok" if self.accepted else "wrong",
            "raw_response": {"accepted": self.accepted},
        }


def test_submit_flag_skips_disabled_provider(monkeypatch):
    state = initial_state("submit01")
    state["final_flag"] = "flag{local}"
    monkeypatch.delenv("FLAG_SUBMIT_PROVIDER", raising=False)

    result = submit_flag(state)

    assert "remote_accepted_flag" not in result
    assert result["submit_results"][-1]["submitted"] is False
    assert result["submit_results"][-1]["provider"] == "disabled"
    assert result["trace"][-1]["event"] == "flag.submit"


def test_submit_flag_records_remote_acceptance(monkeypatch):
    provider = FakeSubmitProvider(accepted=True)
    monkeypatch.setattr("cyberagent.agents.flag_submitter.get_submit_provider", lambda: provider)
    state = initial_state("submit01")
    state["final_flag"] = "flag{remote}"

    result = submit_flag(state)

    assert provider.calls == [("submit01", "flag{remote}")]
    assert result["remote_accepted_flag"] == "flag{remote}"
    assert result["submit_results"][-1]["accepted"] is True
    assert result["findings"][-1]["agent"] == "submit_flag"


def test_submit_flag_records_remote_rejection(monkeypatch):
    provider = FakeSubmitProvider(accepted=False)
    monkeypatch.setattr("cyberagent.agents.flag_submitter.get_submit_provider", lambda: provider)
    state = initial_state("submit01")
    state["final_flag"] = "flag{wrong}"

    result = submit_flag(state)

    assert "remote_accepted_flag" not in result
    assert result["submit_results"][-1]["accepted"] is False
    assert result["submit_results"][-1]["status"] == "rejected"


def test_submit_flag_does_not_resubmit_same_flag(monkeypatch):
    provider = FakeSubmitProvider(accepted=True)
    monkeypatch.setattr("cyberagent.agents.flag_submitter.get_submit_provider", lambda: provider)
    state = initial_state("submit01")
    state["final_flag"] = "flag{remote}"
    state = submit_flag(state)

    result = submit_flag(state)

    assert provider.calls == [("submit01", "flag{remote}")]
    assert len(result["submit_results"]) == 1
    assert result["trace"][-1]["event"] == "flag.submit.skip"
