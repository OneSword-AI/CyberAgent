import time
from dataclasses import dataclass

from cyberagent.signals import Signal, SignalType


@dataclass
class Lease:
    signal_id: str
    agent: str
    expires_at: float


class Blackboard:
    """In-memory structured signal store with short leases."""

    def __init__(self) -> None:
        self._signals: list[Signal] = []
        self._leases: dict[str, Lease] = {}

    def post(self, signal: Signal) -> Signal:
        self._signals.append(signal)
        return signal

    def query(
        self,
        *,
        challenge_id: str | None = None,
        types: set[SignalType] | None = None,
        status: str | None = None,
    ) -> list[Signal]:
        signals = self._signals
        if challenge_id is not None:
            signals = [signal for signal in signals if signal["challenge_id"] == challenge_id]
        if types is not None:
            signals = [signal for signal in signals if signal["type"] in types]
        if status is not None:
            signals = [signal for signal in signals if signal["status"] == status]
        return list(signals)

    def acquire_lease(self, *, signal_id: str, agent: str, ttl: float = 30) -> bool:
        now = time.time()
        lease = self._leases.get(signal_id)
        if lease and lease.expires_at > now and lease.agent != agent:
            return False

        self._leases[signal_id] = Lease(
            signal_id=signal_id,
            agent=agent,
            expires_at=now + ttl,
        )
        return True

    def mark_processed(self, signal_id: str) -> None:
        for signal in self._signals:
            if signal["id"] == signal_id:
                signal["status"] = "processed"
                break
        self._leases.pop(signal_id, None)
