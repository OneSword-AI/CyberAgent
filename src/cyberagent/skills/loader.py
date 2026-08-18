from pathlib import Path
from typing import Any

import yaml

from cyberagent.models import ChallengeState
from cyberagent.skills.models import Skill


CATEGORY_TO_SKILL = {
    "Web": "ctf-web",
    "Pwn": "ctf-pwn",
    "Reverse": "ctf-reverse",
    "Crypto": "ctf-crypto",
    "Misc": "ctf-misc",
    "Forensics": "ctf-forensics",
    "Other": "ctf-misc",
}

AGENT_TO_SKILLS = {
    "web_agent": ("ctf-web",),
    "pwn_agent": ("ctf-pwn",),
    "reverse_agent": ("ctf-reverse", "ctf-mobile"),
    "crypto_agent": ("ctf-crypto",),
    "misc_agent": ("ctf-misc", "ctf-forensics"),
    "forensics_agent": ("ctf-forensics", "ctf-misc"),
    "other_agent": (
        "ctf-web",
        "ctf-pwn",
        "ctf-reverse",
        "ctf-crypto",
        "ctf-misc",
        "ctf-forensics",
        "ctf-osint",
        "ctf-mobile",
        "ctf-cloud",
    ),
}

KEYWORD_TO_SKILL = {
    "web": "ctf-web",
    "http": "ctf-web",
    "https": "ctf-web",
    "cookie": "ctf-web",
    "login": "ctf-web",
    "sql": "ctf-web",
    "pwn": "ctf-pwn",
    "elf": "ctf-pwn",
    "libc": "ctf-pwn",
    "rop": "ctf-pwn",
    "overflow": "ctf-pwn",
    "reverse": "ctf-reverse",
    "rev": "ctf-reverse",
    "apk": "ctf-mobile",
    "ipa": "ctf-mobile",
    "mobile": "ctf-mobile",
    "crypto": "ctf-crypto",
    "rsa": "ctf-crypto",
    "aes": "ctf-crypto",
    "cipher": "ctf-crypto",
    "pcap": "ctf-forensics",
    "memory": "ctf-forensics",
    "forensics": "ctf-forensics",
    "stego": "ctf-misc",
    "qr": "ctf-misc",
    "osint": "ctf-osint",
    "username": "ctf-osint",
    "domain": "ctf-osint",
    "cloud": "ctf-cloud",
    "kubernetes": "ctf-cloud",
    "docker": "ctf-cloud",
    "bucket": "ctf-cloud",
}


def load_skills(skills_dir: str | Path | None = None) -> list[Skill]:
    """Load every valid skill under the configured skills directory."""
    root = _skills_dir(skills_dir)
    if not root.exists():
        return []
    skills: list[Skill] = []
    for path in sorted(root.glob("*/SKILL.md")):
        skills.append(load_skill(path))
    return skills


def load_skill(path: str | Path) -> Skill:
    """Parse one SKILL.md file with YAML frontmatter."""
    skill_path = Path(path)
    text = skill_path.read_text(encoding="utf-8")
    metadata, body = _split_frontmatter(text)
    name = metadata.get("name")
    description = metadata.get("description")
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"skill missing name: {skill_path}")
    if not isinstance(description, str) or not description.strip():
        raise ValueError(f"skill missing description: {skill_path}")
    return {
        "name": name.strip(),
        "description": description.strip(),
        "body": body.strip(),
        "path": str(skill_path),
    }


def load_challenge_skills(
    state: ChallengeState,
    *,
    skills_dir: str | Path | None = None,
) -> list[Skill]:
    """Select relevant CTF skills for a challenge state."""
    skills_by_name = {skill["name"]: skill for skill in load_skills(skills_dir)}
    selected_names = _select_skill_names(state, available=set(skills_by_name))
    return [skills_by_name[name] for name in selected_names if name in skills_by_name]


def render_skill_context(skills: list[Skill], *, max_body_chars: int = 1800) -> str:
    """Render loaded skills as compact prompt context."""
    sections = []
    for skill in skills:
        body = skill["body"][:max_body_chars].strip()
        sections.append(
            "\n".join(
                [
                    f"## {skill['name']}",
                    f"Description: {skill['description']}",
                    body,
                ]
            )
        )
    return "\n\n".join(sections)


def render_specialist_skill_contexts(
    skills: list[Skill],
    *,
    max_body_chars: int = 1800,
) -> dict[str, str]:
    """Render loaded skill context per specialist agent."""
    skills_by_name = {skill["name"]: skill for skill in skills}
    contexts: dict[str, str] = {}
    for agent_name, skill_names in AGENT_TO_SKILLS.items():
        matched = [
            skills_by_name[skill_name]
            for skill_name in skill_names
            if skill_name in skills_by_name
        ]
        if matched:
            contexts[agent_name] = render_skill_context(
                matched,
                max_body_chars=max_body_chars,
            )
    return contexts


def _skills_dir(skills_dir: str | Path | None) -> Path:
    if skills_dir is not None:
        return Path(skills_dir)
    return Path.cwd() / "skills"


def _split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        raise ValueError("skill must start with YAML frontmatter")
    try:
        _, raw_metadata, body = text.split("---", 2)
    except ValueError as exc:
        raise ValueError("skill frontmatter is not closed") from exc
    metadata = yaml.safe_load(raw_metadata) or {}
    if not isinstance(metadata, dict):
        raise ValueError("skill frontmatter must be a mapping")
    return metadata, body


def _select_skill_names(state: ChallengeState, *, available: set[str]) -> list[str]:
    selected: list[str] = []
    for category in state.get("predicted_categories", []):
        skill_name = CATEGORY_TO_SKILL.get(category)
        if skill_name:
            selected.append(skill_name)

    text = _challenge_text(state)
    for keyword, skill_name in KEYWORD_TO_SKILL.items():
        if keyword in text:
            selected.append(skill_name)

    if state.get("remote_targets"):
        selected.append("ctf-web")
    for attachment in state.get("attachments", []):
        selected.extend(_skills_from_attachment(str(attachment)))

    selected = [name for name in dict.fromkeys(selected) if name in available]
    if selected:
        return selected
    return ["ctf-misc"] if "ctf-misc" in available else []


def _challenge_text(state: ChallengeState) -> str:
    parts = [
        state.get("title", ""),
        state.get("description", ""),
        state.get("category_hint", ""),
        " ".join(state.get("remote_targets", [])),
        " ".join(state.get("attachments", [])),
    ]
    return " ".join(part for part in parts if part).lower()


def _skills_from_attachment(path: str) -> list[str]:
    suffix = Path(path).suffix.lower()
    if suffix in {".apk", ".aab", ".ipa"}:
        return ["ctf-mobile", "ctf-reverse"]
    if suffix in {".pcap", ".pcapng", ".mem", ".raw", ".dmp"}:
        return ["ctf-forensics"]
    if suffix in {".elf", ".so"}:
        return ["ctf-pwn", "ctf-reverse"]
    if suffix in {".zip", ".7z", ".rar", ".png", ".jpg", ".jpeg", ".wav"}:
        return ["ctf-misc", "ctf-forensics"]
    return []
