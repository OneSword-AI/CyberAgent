from cyberagent.blackboard import Blackboard
from cyberagent.signals import is_broadcast, is_visible_to, make_signal


def test_blackboard_posts_and_queries_signals():
    blackboard = Blackboard()
    signal = make_signal(
        type="challenge_input",
        challenge_id="bb01",
        source="test",
        payload={"title": "demo"},
        provenance="input",
    )

    blackboard.post(signal)

    assert blackboard.query(challenge_id="bb01", types={"challenge_input"}) == [signal]


def test_blackboard_short_lease_prevents_duplicate_processing():
    blackboard = Blackboard()
    signal = make_signal(
        type="challenge_input",
        challenge_id="bb01",
        source="test",
        payload={},
        provenance="input",
    )
    blackboard.post(signal)

    assert blackboard.acquire_lease(signal_id=signal["id"], agent="observer") is True
    assert blackboard.acquire_lease(signal_id=signal["id"], agent="analyst") is False

    blackboard.mark_processed(signal["id"])

    assert blackboard.query(status="processed") == [signal]


def test_blackboard_filters_recipients_and_supports_failure_lifecycle():
    blackboard = Blackboard()
    direct = make_signal(
        type="observation",
        challenge_id="bb02",
        source="test",
        payload={},
        provenance="inference",
        recipients=["observer"],
    )
    broadcast = make_signal(
        type="observation",
        challenge_id="bb02",
        source="test",
        payload={},
        provenance="inference",
    )
    blackboard.post(direct)
    blackboard.post(broadcast)

    assert is_broadcast(broadcast)
    assert not is_broadcast(direct)
    assert is_visible_to(direct, "observer")
    assert not is_visible_to(direct, "analyst")
    assert blackboard.query(recipient="analyst") == [broadcast]

    assert blackboard.claim_message(signal_id=direct["id"], agent="observer")
    assert direct["status"] == "processing"
    assert blackboard.lease(signal_id=direct["id"]) is not None
    blackboard.mark_failed(direct["id"])
    assert direct["status"] == "failed"
    assert blackboard.lease(signal_id=direct["id"]) is None
