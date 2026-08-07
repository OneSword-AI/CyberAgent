from collections.abc import Callable

from cyberagent.agents.constants import KNOWN_AGENT_NAMES
from cyberagent.agents.specialists import (
    crypto_agent,
    forensics_agent,
    misc_agent,
    other_agent,
    pwn_agent,
    reverse_agent,
    web_agent,
)
from cyberagent.models import ChallengeState


AgentNode = Callable[[ChallengeState], ChallengeState]


SPECIALIST_NODES: dict[str, AgentNode] = {
    "web_agent": web_agent,
    "pwn_agent": pwn_agent,
    "reverse_agent": reverse_agent,
    "crypto_agent": crypto_agent,
    "misc_agent": misc_agent,
    "forensics_agent": forensics_agent,
    "other_agent": other_agent,
}

SPECIALIST_ORDER = tuple(SPECIALIST_NODES)

missing_agents = set(KNOWN_AGENT_NAMES) - set(SPECIALIST_NODES)
if missing_agents:
    raise RuntimeError(f"missing specialist node(s): {sorted(missing_agents)}")
