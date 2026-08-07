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
SignalStatus = Literal["pending", "processing", "processed", "failed"]

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
    status: SignalStatus
    recipients: NotRequired[list[str]]
    confidence: NotRequired[float]


def is_broadcast(signal: Signal) -> bool:
    """Return whether a signal has no recipient restriction."""
    return not signal.get("recipients")


def is_visible_to(signal: Signal, agent: str) -> bool:
    """Return whether an agent may consume a signal."""
    return is_broadcast(signal) or agent in signal["recipients"]


def is_pending(signal: Signal) -> bool:
    return signal["status"] == "pending"


def is_terminal(signal: Signal) -> bool:
    return signal["status"] in {"processed", "failed"}


def make_signal(
    *,
    type: SignalType,
    challenge_id: str,
    source: str,
    payload: dict[str, Any],
    provenance: Provenance,
    parent_ids: list[str] | None = None,
    confidence: float | None = None,
    recipients: list[str] | None = None,
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
    if recipients is not None:
        signal["recipients"] = recipients
    if confidence is not None:
        signal["confidence"] = confidence
    return signal
