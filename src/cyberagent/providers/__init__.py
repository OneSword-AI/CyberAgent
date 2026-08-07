"""Challenge data providers."""

from cyberagent.providers.base import ChallengeData, ChallengeProvider
from cyberagent.providers.fetch import fetch_challenge

__all__ = ["ChallengeData", "ChallengeProvider", "fetch_challenge"]
