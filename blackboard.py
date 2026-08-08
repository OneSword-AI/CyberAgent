"""Shared blackboard — JSON-persisted signal store with lease management."""
from __future__ import annotations
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

LEASE_TTL = 30.0  # seconds


class SType(str, Enum):
    RAW_INPUT           = "RAW_INPUT"
    OBSERVATION         = "OBSERVATION"
    HYPOTHESIS          = "HYPOTHESIS"
    ANALYSIS            = "ANALYSIS"
    QUESTION            = "QUESTION"
    EVIDENCE            = "EVIDENCE"
    MEMORY_PRIOR        = "MEMORY_PRIOR"
    CANDIDATE_CONCLUSION = "CANDIDATE_CONCLUSION"
    CONCLUSION          = "CONCLUSION"
    REJECTION           = "REJECTION"


class SStatus(str, Enum):
    PENDING    = "PENDING"
    LEASED     = "LEASED"
    RETIRED    = "RETIRED"   # fully retired (manual or explicit sink)


@dataclass
class Signal:
    type: str
    source: str
    payload: dict[str, Any]
    id: str                       = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str                = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str                   = field(default=SStatus.PENDING)
    lease_holder: Optional[str]   = None
    lease_expiry: Optional[float] = None
    round_num: int                = 0
    parent_id: Optional[str]      = None
    # Multi-consumer: each agent records itself here after handling
    processed_by: list             = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Signal":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class Blackboard:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.signals: list[Signal] = []
        self._load()

    # ── persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self.signals = [Signal.from_dict(s) for s in raw.get("signals", [])]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"signals": [s.to_dict() for s in self.signals]}, indent=2),
            encoding="utf-8",
        )

    # ── signal operations ─────────────────────────────────────────────────────

    def post(self, signal: Signal) -> str:
        self.signals.append(signal)
        self.save()
        return signal.id

    def pending_for(self, types: list[str], agent_id: str) -> list[Signal]:
        """Return signals this agent has not yet handled.
        Each agent tracks itself in processed_by; leases prevent duplicate work
        within the same agent.
        """
        now = time.time()
        result: list[Signal] = []
        for s in self.signals:
            if s.type not in types:
                continue
            if s.status == SStatus.RETIRED:
                continue
            if agent_id in s.processed_by:
                continue  # this agent already handled it
            if s.status == SStatus.LEASED and s.lease_expiry and s.lease_expiry < now:
                s.status      = SStatus.PENDING
                s.lease_holder = None
                s.lease_expiry = None
            if s.status == SStatus.PENDING:
                result.append(s)
        return result

    def acquire_lease(self, signal_id: str, agent_id: str) -> bool:
        """Atomically acquire a short lease. Returns False if already leased by another."""
        now = time.time()
        for s in self.signals:
            if s.id != signal_id:
                continue
            if agent_id in s.processed_by:
                return False  # already done by this agent
            expired = s.status == SStatus.LEASED and s.lease_expiry and s.lease_expiry < now
            if s.status == SStatus.PENDING or expired:
                s.status       = SStatus.LEASED
                s.lease_holder = agent_id
                s.lease_expiry = now + LEASE_TTL
                self.save()
                return True
            return False
        return False

    def mark_processed(self, signal_id: str, agent_id: str) -> None:
        """Record this agent as having processed the signal; release lease.
        Signal stays visible to other agents (multi-consumer broadcast).
        """
        for s in self.signals:
            if s.id == signal_id and s.lease_holder == agent_id:
                if agent_id not in s.processed_by:
                    s.processed_by.append(agent_id)
                s.status       = SStatus.PENDING  # back to PENDING for other consumers
                s.lease_holder = None
                s.lease_expiry = None
                self.save()
                return

    def retire(self, signal_id: str) -> None:
        """Explicitly retire a signal so no further agents process it."""
        for s in self.signals:
            if s.id == signal_id:
                s.status = SStatus.RETIRED
                self.save()
                return

    # ── query helpers ─────────────────────────────────────────────────────────

    def evidence_for(self, subject: str) -> list[Signal]:
        """Return active EVIDENCE signals about a subject.
        MEMORY_PRIOR signals are intentionally excluded here.
        """
        return [
            s for s in self.signals
            if s.type == SType.EVIDENCE
            and s.payload.get("subject") == subject
            and s.status != SStatus.RETIRED
        ]

    def memory_priors_for(self, subject: str) -> list[Signal]:
        return [
            s for s in self.signals
            if s.type == SType.MEMORY_PRIOR
            and s.payload.get("subject") == subject
        ]

    def conclusions(self) -> list[Signal]:
        return [s for s in self.signals if s.type == SType.CONCLUSION]

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for s in self.signals:
            counts[s.type] = counts.get(s.type, 0) + 1
        return counts
