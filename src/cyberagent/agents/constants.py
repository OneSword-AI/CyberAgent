CATEGORY_TO_AGENT = {
    "Web": "web_agent",
    "Pwn": "pwn_agent",
    "Reverse": "reverse_agent",
    "Crypto": "crypto_agent",
    "Misc": "misc_agent",
    "Forensics": "forensics_agent",
    "Other": "other_agent",
}

KNOWN_CATEGORIES = tuple(CATEGORY_TO_AGENT)
KNOWN_AGENT_NAMES = tuple(CATEGORY_TO_AGENT.values())
KNOWN_COMPLEXITIES = ("simple", "medium", "complex")
