import os

from cyberagent.providers.base import ChallengeProvider
from cyberagent.providers.http_json import HttpJsonProvider
from cyberagent.providers.local_json import LocalJsonProvider


def get_provider() -> ChallengeProvider:
    provider_name = os.getenv("CHALLENGE_PROVIDER", "http_json")

    providers: dict[str, ChallengeProvider] = {
        HttpJsonProvider.name: HttpJsonProvider(),
        LocalJsonProvider.name: LocalJsonProvider(),
    }

    try:
        return providers[provider_name]
    except KeyError as exc:
        supported = ", ".join(sorted(providers))
        raise ValueError(f"unsupported challenge provider: {provider_name}; supported: {supported}") from exc
