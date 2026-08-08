import copy
import time
from dataclasses import dataclass

from cyberagent.signals import Signal, SignalType, is_broadcast, is_visible_to


@dataclass
class Lease:
    signal_id: str
    agent: str
    expires_at: float


class Blackboard:
    """In-memory structured signal store with short leases."""

    def __init__(self, signals: list[Signal] | None = None) -> None:
        self._signals: list[Signal] = copy.deepcopy(signals or [])
        self._leases: dict[str, Lease] = {}

    def post(self, signal: Signal) -> Signal:
        if any(existing["id"] == signal["id"] for existing in self._signals):
            raise ValueError(f"signal already exists: {signal['id']}")
        self._signals.append(signal)
        return signal

    def query(
        self,
        *,
        challenge_id: str | None = None,
        types: set[SignalType] | None = None,
        status: str | None = None,
        recipient: str | None = None,
    ) -> list[Signal]:
        signals = self._signals
        if challenge_id is not None:
            signals = [signal for signal in signals if signal["challenge_id"] == challenge_id]
        if types is not None:
            signals = [signal for signal in signals if signal["type"] in types]
        if status is not None:
            signals = [signal for signal in signals if signal["status"] == status]
        if recipient is not None:
            signals = [
                signal
                for signal in signals
                if is_visible_to(signal, recipient)
                and recipient not in signal.get("delivered_to", [])
                and (signal["source"] != recipient or not is_broadcast(signal))
            ]
        return list(signals)

    def acquire_lease(self, *, signal_id: str, agent: str, ttl: float = 30) -> bool:
        """Claim a visible pending signal for an agent."""
        signal = next((item for item in self._signals if item["id"] == signal_id), None)
        if signal is None or signal["status"] != "pending" or not is_visible_to(signal, agent):
            return False

        now = time.time()
        lease = self._leases.get(signal_id)
        if lease and lease.expires_at > now and lease.agent != agent:
            return False
        if lease and lease.expires_at <= now:
            self._leases.pop(signal_id, None)

        self._leases[signal_id] = Lease(
            signal_id=signal_id,
            agent=agent,
            expires_at=now + ttl,
        )
        signal["status"] = "processing"
        delivered_to = signal.setdefault("delivered_to", [])
        if agent not in delivered_to:
            delivered_to.append(agent)
        return True

    def claim(self, *, signal_id: str, agent: str, ttl: float = 30) -> bool:
        return self.acquire_lease(signal_id=signal_id, agent=agent, ttl=ttl)

    def claim_message(self, *, signal_id: str, agent: str, ttl: float = 30) -> bool:
        return self.acquire_lease(signal_id=signal_id, agent=agent, ttl=ttl)

    def mark_processing(self, signal_id: str) -> None:
        for signal in self._signals:
            if signal["id"] == signal_id:
                signal["status"] = "processing"
                break

    def mark_processed(self, signal_id: str) -> None:
        self.mark_completed(signal_id)

    def mark_completed(self, signal_id: str) -> None:
        for signal in self._signals:
            if signal["id"] == signal_id:
                recipients = signal.get("recipients", [])
                delivered_to = signal.get("delivered_to", [])
                if recipients and any(agent not in delivered_to for agent in recipients):
                    signal["status"] = "pending"
                else:
                    signal["status"] = "processed"
                break
        self.release_lease(signal_id=signal_id)

    def mark_failed(self, signal_id: str) -> None:
        for signal in self._signals:
            if signal["id"] == signal_id:
                signal["status"] = "failed"
                break
        self.release_lease(signal_id=signal_id)

    def release_lease(self, *, signal_id: str) -> None:
        self._leases.pop(signal_id, None)

    def snapshot(self) -> list[Signal]:
        """Return the current signal collection for persistence in graph state."""
        return list(self._signals)

    def lease(self, *, signal_id: str) -> Lease | None:
        lease = self._leases.get(signal_id)
        if lease is not None and lease.expires_at <= time.time():
            self._leases.pop(signal_id, None)
            for signal in self._signals:
                if signal["id"] == signal_id and signal["status"] == "processing":
                    signal["status"] = "pending"
                    break
            return None
        return lease
