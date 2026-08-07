from dataclasses import dataclass


ALLOWED_ACTION_TYPES = {
    "http.request",
    "file.inspect",
    "attachment.download",
    "shell.run",
    "llm.invoke",
    "provider.fetch",
    "flag.submit",
}
DENIED_ACTION_TYPES = {
    "env.read_all",
    "credential.dump",
    "platform.admin",
}


@dataclass
class SafetyDecision:
    allow: bool
    reason: str
    action_type: str
    caller: str


class L0SafetyGate:
    """Minimal L0 gate for external actions."""

    def evaluate(self, *, action_type: str, caller: str, params: dict | None = None) -> SafetyDecision:
        params = params or {}
        if action_type in DENIED_ACTION_TYPES:
            return SafetyDecision(False, "action type is explicitly denied", action_type, caller)
        if action_type not in ALLOWED_ACTION_TYPES:
            return SafetyDecision(False, "unknown action type", action_type, caller)
        if _mentions_secret(params):
            return SafetyDecision(False, "action references protected credentials", action_type, caller)
        return SafetyDecision(True, "allowed", action_type, caller)


def _mentions_secret(params: dict) -> bool:
    text = str(params).upper()
    return any(name in text for name in ("OPENAI_API_KEY", "CTF_API_TOKEN", "PASSWORD", "SECRET"))
