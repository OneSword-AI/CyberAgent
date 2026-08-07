import time
import uuid
from typing import Any, Literal, NotRequired, TypedDict


SignalType = Literal[
    "challenge_input",
    "observation",
    "hypothesis",
    "evidence",
    "memory_prior",
    "critic_report",
    "feedback",
]

Provenance = Literal["input", "inference", "direct_tool", "memory_prior", "critic"]


class Signal(TypedDict):
    id: str
    type: SignalType
    challenge_id: str
    source: str
    payload: dict[str, Any]
    provenance: Provenance
    ts: float
    parent_ids: list[str]
    status: str
    confidence: NotRequired[float]


def make_signal(
    *,
    type: SignalType,
    challenge_id: str,
    source: str,
    payload: dict[str, Any],
    provenance: Provenance,
    parent_ids: list[str] | None = None,
    confidence: float | None = None,
) -> Signal:
    signal: Signal = {
        "id": str(uuid.uuid4()),
        "type": type,
        "challenge_id": challenge_id,
        "source": source,
        "payload": payload,
        "provenance": provenance,
        "ts": time.time(),
        "parent_ids": parent_ids or [],
        "status": "pending",
    }
    if confidence is not None:
        signal["confidence"] = confidence
    return signal
