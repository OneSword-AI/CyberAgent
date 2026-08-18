from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyberagent.agents.registry import SPECIALIST_AGENTS
from cyberagent.agents.specialist_signals import make_specialist_result_signal
from cyberagent.agents.specialists import apply_specialist_result
from cyberagent.blackboard import Blackboard
from cyberagent.evidence import add_finding
from cyberagent.models import ChallengeState, SpecialistResult
from cyberagent.signals import Signal, is_visible_to
from cyberagent.trace import add_trace_event


@dataclass(frozen=True)
class BlackboardSpecialistAgent:
    """Autonomous wrapper for a specialist that consumes blackboard tasks."""

    name: str
    subscriptions: set[str]
    categories: set[str]
    keywords: set[str]

    def can_process(self, signal: Signal) -> bool:
        return signal["type"] in self.subscriptions

    def matches(self, signal: Signal, state: ChallengeState) -> bool:
        if not self.can_process(signal) or not is_visible_to(signal, self.name):
            return False
        if self.name in signal.get("delivered_to", []):
            return False
        if self.name in signal.get("recipients", []):
            return True
        payload = signal.get("payload", {})
        if self.name in _payload_agents(payload):
            return True
        if self.categories & _payload_categories(payload, state):
            return True
        text = _signal_text(signal, state)
        return any(keyword in text for keyword in self.keywords)

    def process(self, state: ChallengeState) -> SpecialistResult:
        return SPECIALIST_AGENTS[self.name]({**state, "active_agents": [self.name]})


BLACKBOARD_SPECIALISTS = {
    "web_agent": BlackboardSpecialistAgent(
        name="web_agent",
        subscriptions={"challenge_input", "observation", "hypothesis", "feedback"},
        categories={"Web"},
        keywords={"web", "http", "https", "url", "cookie", "login", "sql", "xss", "upload"},
    ),
    "pwn_agent": BlackboardSpecialistAgent(
        name="pwn_agent",
        subscriptions={"challenge_input", "observation", "hypothesis", "feedback"},
        categories={"Pwn"},
        keywords={"pwn", "elf", "libc", "rop", "overflow", "nc ", "shellcode"},
    ),
    "reverse_agent": BlackboardSpecialistAgent(
        name="reverse_agent",
        subscriptions={"challenge_input", "observation", "hypothesis", "feedback"},
        categories={"Reverse"},
        keywords={"reverse", "rev", "binary", "apk", "decompile", "license", "vm"},
    ),
    "crypto_agent": BlackboardSpecialistAgent(
        name="crypto_agent",
        subscriptions={"challenge_input", "observation", "hypothesis", "feedback"},
        categories={"Crypto"},
        keywords={"crypto", "rsa", "aes", "cipher", "encrypt", "decrypt", "ecc"},
    ),
    "misc_agent": BlackboardSpecialistAgent(
        name="misc_agent",
        subscriptions={"challenge_input", "observation", "hypothesis", "feedback"},
        categories={"Misc", "Other"},
        keywords={"misc", "stego", "qr", "base64", "zip", "audio", "image"},
    ),
    "forensics_agent": BlackboardSpecialistAgent(
        name="forensics_agent",
        subscriptions={"challenge_input", "observation", "hypothesis", "feedback"},
        categories={"Forensics"},
        keywords={"forensics", "pcap", "pcapng", "memory", "disk", "traffic", "wireshark"},
    ),
    "other_agent": BlackboardSpecialistAgent(
        name="other_agent",
        subscriptions={"feedback"},
        categories={"Other"},
        keywords={"other", "unknown"},
    ),
}


def run_blackboard_specialists(state: ChallengeState) -> ChallengeState:
    """Let specialist Agents claim matching blackboard tasks and process them."""
    challenge_id = state.get("challenge_id", "")
    board = Blackboard(state.get("signals", []))
    next_state = state
    claimed_agents: list[str] = []
    processed = 0

    for signal in board.query(challenge_id=challenge_id, status="pending"):
        agents = _matching_agents(signal, next_state)
        _materialize_recipients(signal, agents)
        for agent in agents:
            if not board.claim(signal_id=signal["id"], agent=agent.name):
                continue

            try:
                result = agent.process(next_state)
            except Exception:
                board.mark_failed(signal["id"])
                raise

            next_state = apply_specialist_result(next_state, result)
            board.post(
                make_specialist_result_signal(
                    next_state,
                    result,
                    parent_ids=[signal["id"]],
                )
            )
            board.mark_completed(signal["id"])
            claimed_agents.append(agent.name)
            processed += 1

    next_state = {
        **next_state,
        "signals": board.snapshot(),
        "active_agents": list(dict.fromkeys(claimed_agents)),
        "published_specialist_results": len(next_state.get("specialist_results", [])),
    }
    next_state = add_trace_event(
        next_state,
        node="blackboard_specialists",
        event="blackboard.dispatch",
        details={
            "processed": processed,
            "active_agents": next_state["active_agents"],
            "mode": "autonomous_signal_competition",
        },
    )
    return add_finding(
        next_state,
        agent="blackboard_specialists",
        summary=f"Processed {processed} blackboard specialist task(s).",
        evidence={
            "active_agents": next_state["active_agents"],
            "mode": "autonomous_signal_competition",
        },
    )


def _matching_agents(
    signal: Signal,
    state: ChallengeState,
) -> list[BlackboardSpecialistAgent]:
    return [
        agent
        for agent in BLACKBOARD_SPECIALISTS.values()
        if agent.matches(signal, state)
    ]


def _materialize_recipients(
    signal: Signal,
    agents: list[BlackboardSpecialistAgent],
) -> None:
    if signal.get("recipients"):
        return
    recipients = [agent.name for agent in agents]
    if recipients:
        signal["recipients"] = recipients


def _payload_agents(payload: dict[str, Any]) -> set[str]:
    values = payload.get("next_agents", [])
    if not isinstance(values, list):
        return set()
    return {item for item in values if isinstance(item, str)}


def _payload_categories(payload: dict[str, Any], state: ChallengeState) -> set[str]:
    values: list[Any] = []
    for key in ("predicted_categories", "categories"):
        if isinstance(payload.get(key), list):
            values.extend(payload[key])
    values.extend(state.get("predicted_categories", []))
    return {item for item in values if isinstance(item, str)}


def _signal_text(signal: Signal, state: ChallengeState) -> str:
    payload = signal.get("payload", {})
    parts = [
        signal.get("type", ""),
        signal.get("source", ""),
        str(payload),
        state.get("title", ""),
        state.get("description", ""),
        state.get("category_hint", ""),
        " ".join(state.get("remote_targets", [])),
        " ".join(state.get("attachments", [])),
    ]
    for attachment in state.get("downloaded_attachments", []):
        path = str(attachment.get("path", ""))
        parts.append(path)
        parts.append(Path(path).suffix)
    return " ".join(part for part in parts if part).lower()
