from cyberagent.models import ChallengeState
from cyberagent.providers.normalizer import normalize_challenge
from cyberagent.providers.registry import get_provider


def fetch_challenge(state: ChallengeState) -> ChallengeState:
    challenge_id = state.get("challenge_id")
    if not challenge_id:
        raise ValueError("challenge_id is required to fetch challenge metadata")

    provider = get_provider()
    raw = provider.fetch(challenge_id)
    challenge = normalize_challenge(raw)

    return {
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
