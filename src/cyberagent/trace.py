import time
import uuid
from typing import Any

from cyberagent.models import ChallengeState


def add_trace_event(
    state: ChallengeState,
    *,
    node: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> ChallengeState:
    """Append a trace event to the challenge state."""
    return {
        **state,
        "trace": [
            *state.get("trace", []),
            {
                "id": str(uuid.uuid4()),
                "ts": time.time(),
                "challenge_id": state.get("challenge_id", ""),
                "node": node,
                "event": event,
                "details": details or {},
            },
        ],
    }
