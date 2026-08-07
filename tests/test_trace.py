from cyberagent.graph import initial_state
from cyberagent.trace import add_trace_event


def test_add_trace_event_appends_event_without_mutating_original_state():
    state = initial_state("trace01")

    next_state = add_trace_event(
        state,
        node="classify_challenge",
        event="llm.classify",
        details={"category": "Web"},
    )

    assert state["trace"] == []
    assert len(next_state["trace"]) == 1
    event = next_state["trace"][0]
    assert event["challenge_id"] == "trace01"
    assert event["node"] == "classify_challenge"
    assert event["event"] == "llm.classify"
    assert event["details"] == {"category": "Web"}
    assert event["id"]
    assert event["ts"]
