from typing import Any, Protocol, TypedDict


class ChallengeData(TypedDict):
    title: str
    description: str
    attachments: list[str]
    remote_targets: list[str]
    category_hint: str | None
    flag_format: str | None
    raw: dict[str, Any]


class ChallengeProvider(Protocol):
    name: str

    def fetch(self, challenge_id: str) -> dict[str, Any]:
        """Return raw challenge data from one source."""
        ...
