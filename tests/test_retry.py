from cyberagent.agents.retry import retry_agent
from cyberagent.graph import initial_state


def test_retry_agent_increments_retry_count_and_records_failed_attempt():
    state = initial_state("retry01")
    state["candidate_flags"] = ["not-a-flag"]

    result = retry_agent(state)

    assert result["retry_count"] == 1
    assert result["failed_attempts"][-1]["candidate_flags"] == ["not-a-flag"]
    assert result["findings"][-1]["agent"] == "retry_agent"
    assert result["trace"][-1]["event"] == "retry.schedule"
