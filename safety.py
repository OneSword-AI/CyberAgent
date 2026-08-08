"""L0 safety gate — all external actions pass through here."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any


class ActionType(str, Enum):
    READ_FILE   = "READ_FILE"
    WRITE_FILE  = "WRITE_FILE"
    EXECUTE_CMD = "EXECUTE_CMD"
    NETWORK_CALL = "NETWORK_CALL"
    SCAN_PORT   = "SCAN_PORT"
    POST_SIGNAL = "POST_SIGNAL"   # internal — always allowed


# Patterns that immediately trigger deny regardless of type
_DENY_PATTERNS: list[str] = [
    "rm -rf", "mkfs", "dd if=", ":(){",
    "/etc/shadow", "/etc/passwd", "chmod 777",
]

# Action types allowed in MVP (others are blocked)
_ALLOWED_TYPES: set[ActionType] = {
    ActionType.READ_FILE,
    ActionType.WRITE_FILE,
    ActionType.EXECUTE_CMD,
    ActionType.NETWORK_CALL,
    ActionType.SCAN_PORT,
    ActionType.POST_SIGNAL,
}


@dataclass
class ActionRequest:
    action_type: ActionType
    actor: str
    target: str
    params: dict[str, Any]


@dataclass
class SafetyVerdict:
    allowed: bool
    reason: str


def l0_check(req: ActionRequest) -> SafetyVerdict:
    """Hard deny-by-default gate. Only explicitly allowed actions pass."""
    # Always allow internal signal posting
    if req.action_type == ActionType.POST_SIGNAL:
        return SafetyVerdict(allowed=True, reason="internal signal post")

    # Pattern-level block on target/params
    combined = f"{req.target} {req.params}".lower()
    for pattern in _DENY_PATTERNS:
        if pattern in combined:
            return SafetyVerdict(allowed=False, reason=f"denied pattern: {pattern!r}")

    if req.action_type not in _ALLOWED_TYPES:
        return SafetyVerdict(
            allowed=False,
            reason=f"{req.action_type} not in MVP allowlist",
        )

    return SafetyVerdict(allowed=True, reason="passed L0")
