from cyberagent.blackboard import Blackboard
from cyberagent.signals import make_signal


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
