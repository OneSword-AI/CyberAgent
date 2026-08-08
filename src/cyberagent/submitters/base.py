from typing import Any, Protocol, TypedDict, runtime_checkable


class SubmitResult(TypedDict):
    submitted: bool
    accepted: bool | None
    status: str
    message: str
    raw_response: dict[str, Any] | None


@runtime_checkable
class SubmitProvider(Protocol):
    name: str

    def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        ...
