from collections.abc import Callable

from cyberagent.agents.constants import KNOWN_AGENT_NAMES
from cyberagent.agents.specialists import (
    apply_specialist_result,
    crypto_agent,
    forensics_agent,
    misc_agent,
    other_agent,
    pwn_agent,
    reverse_agent,
    web_agent,
)
from cyberagent.models import ChallengeState, SpecialistResult

SpecialistAgent = Callable[[ChallengeState], SpecialistResult]
AgentNode = Callable[[ChallengeState], ChallengeState]


def _make_state_node(name: str, agent: SpecialistAgent) -> AgentNode:
    def node(state: ChallengeState) -> ChallengeState:
        result = agent(state)
        if result["agent"] != name:
            raise ValueError(
                f"specialist result agent mismatch: expected {name}, got {result['agent']}"
            )
        return apply_specialist_result(state, result)

    return node


SPECIALIST_AGENTS: dict[str, SpecialistAgent] = {
    "web_agent": web_agent,
    "pwn_agent": pwn_agent,
    "reverse_agent": reverse_agent,
    "crypto_agent": crypto_agent,
    "misc_agent": misc_agent,
    "forensics_agent": forensics_agent,
    "other_agent": other_agent,
}

SPECIALIST_ORDER = tuple(SPECIALIST_AGENTS)
SPECIALIST_NODES: dict[str, AgentNode] = {
    name: _make_state_node(name, agent)
    for name, agent in SPECIALIST_AGENTS.items()
}

missing_agents = set(KNOWN_AGENT_NAMES) - set(SPECIALIST_AGENTS)
if missing_agents:
    raise RuntimeError(f"missing specialist node(s): {sorted(missing_agents)}")
