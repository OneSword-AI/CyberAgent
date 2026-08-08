"""Abstract base class for all blackboard agents."""
from __future__ import annotations
import logging
from abc import ABC, abstractmethod
from typing import Any

from blackboard import Blackboard, Signal, SType

logger = logging.getLogger(__name__)


class AgentBase(ABC):
    """
    Agents self-select work by subscribing to signal types.
    They must acquire a lease before processing to prevent double-handling.
    """

    # Subclasses declare which signal types they consume
    subscribes_to: list[str] = []

    def __init__(self, agent_id: str, config: dict[str, Any], blackboard: Blackboard) -> None:
        self.agent_id   = agent_id
        self.config     = config
        self.blackboard = blackboard

    # ── main entry ────────────────────────────────────────────────────────────

    def run_once(self, round_num: int) -> int:
        """Process all available matching signals. Returns number handled."""
        handled = 0
        pending = self.blackboard.pending_for(self.subscribes_to, self.agent_id)
        for signal in pending:
            if not self.blackboard.acquire_lease(signal.id, self.agent_id):
                continue  # Another agent (or concurrent run) grabbed it first
            try:
                logger.debug("[%s] handling %s/%s", self.agent_id, signal.type, signal.id[:8])
                self._handle(signal, round_num)
                self.blackboard.mark_processed(signal.id, self.agent_id)
                handled += 1
            except Exception as exc:
                logger.error("[%s] error on %s: %s", self.agent_id, signal.id[:8], exc)
                self.blackboard.mark_processed(signal.id, self.agent_id)
        return handled

    # ── helpers ───────────────────────────────────────────────────────────────

    def post(self, sig_type: str, payload: dict, parent: Signal | None = None,
             round_num: int = 0) -> str:
        sig = Signal(
            type=sig_type,
            source=self.agent_id,
            payload=payload,
            parent_id=parent.id if parent else None,
            round_num=round_num,
        )
        return self.blackboard.post(sig)

    # ── abstract ──────────────────────────────────────────────────────────────

    @abstractmethod
    def _handle(self, signal: Signal, round_num: int) -> None:
        """Process a single signal. Called only after lease is held."""
