from cyberagent.evidence import add_evidence, add_finding, add_hypothesis, make_finding
from cyberagent.graph import initial_state


def test_make_finding_defaults_evidence():
    finding = make_finding(agent="agent", summary="summary")

    assert finding == {
        "kind": "finding",
        "agent": "agent",
        "summary": "summary",
        "evidence": {},
    }


def test_add_finding_appends_without_mutating_original_state():
    state = initial_state("1")

    next_state = add_finding(
        state,
        agent="classifier",
        summary="classified",
        evidence={"category": "Web"},
    )

    assert state["findings"] == []
    assert next_state["findings"][-1]["agent"] == "classifier"
    assert next_state["findings"][-1]["evidence"] == {"category": "Web"}


def test_add_evidence_and_hypothesis_set_kind():
    state = initial_state("1")

    state = add_evidence(state, agent="web_agent", summary="HTTP target found")
    state = add_hypothesis(state, agent="web_agent", summary="May be login bypass")

    assert state["findings"][0]["kind"] == "evidence"
    assert state["findings"][1]["kind"] == "hypothesis"
