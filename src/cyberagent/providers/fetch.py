from cyberagent.models import ChallengeState
from cyberagent.providers.normalizer import normalize_challenge
from cyberagent.providers.registry import get_provider
from cyberagent.trace import add_trace_event


def fetch_challenge(state: ChallengeState) -> ChallengeState:
    challenge_id = state.get("challenge_id")
    if not challenge_id:
        raise ValueError("challenge_id is required to fetch challenge metadata")

    provider = get_provider()
    raw = provider.fetch(challenge_id)
    challenge = normalize_challenge(raw)

    next_state: ChallengeState = {
        **state,
        "provider_name": provider.name,
        "raw_challenge": challenge["raw"],
        "title": challenge["title"],
        "description": challenge["description"],
        "category_hint": challenge["category_hint"],
        "flag_format": challenge["flag_format"],
        "attachments": challenge["attachments"],
        "remote_targets": challenge["remote_targets"],
    }
    return add_trace_event(
        next_state,
        node="fetch_challenge",
        event="challenge.fetch",
        details={
            "provider": provider.name,
            "title": challenge["title"],
            "attachments": len(challenge["attachments"]),
            "remote_targets": len(challenge["remote_targets"]),
        },
    )
