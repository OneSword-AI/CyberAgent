from typing import TypedDict


class Skill(TypedDict):
    """Parsed CTF skill loaded from a SKILL.md file."""

    name: str
    description: str
    body: str
    path: str
