from cyberagent.models import ChallengeState


KNOWN_CATEGORIES = ("Web", "Pwn", "Reverse", "Crypto", "Misc", "Forensics", "Other")


def classify_challenge(state: ChallengeState) -> ChallengeState:
    """Classify the challenge with deterministic hints.

    This is intentionally lightweight. Replace or augment it with an LLM-backed
    classifier after the fetch -> state -> graph path is stable.
    """
    text = " ".join(
        [
            state.get("title", ""),
            state.get("description", ""),
            state.get("category_hint", "") or "",
            " ".join(state.get("attachments", [])),
            " ".join(state.get("remote_targets", [])),
        ]
    ).lower()

    categories = _classify_from_text(text)
    if not categories:
        categories = ["Other"]

    finding = {
        "agent": "classifier",
        "summary": f"Predicted challenge category: {', '.join(categories)}",
        "evidence": {
            "title": state.get("title", ""),
            "category_hint": state.get("category_hint"),
        },
    }

    return {
        **state,
        "predicted_categories": categories,
        "findings": [*state.get("findings", []), finding],
    }


def _classify_from_text(text: str) -> list[str]:
    scores = {
        "Web": _count(text, "web", "http", "url", "cookie", "xss", "sqli", "sql", "upload"),
        "Pwn": _count(text, "pwn", "elf", "libc", "nc ", "overflow", "rop", "shell"),
        "Reverse": _count(text, "reverse", "rev", "binary", "apk", "decompile", "license"),
        "Crypto": _count(text, "crypto", "rsa", "ecc", "aes", "cipher", "encrypt", "decrypt"),
        "Forensics": _count(text, "forensics", "pcap", "memory", "disk", "traffic", "wireshark"),
        "Misc": _count(text, "misc", "stego", "zip", "qr", "base64", "image", "audio"),
    }

    max_score = max(scores.values())
    if max_score == 0:
        return []
    return [category for category in scores if scores[category] == max_score]


def _count(text: str, *keywords: str) -> int:
    return sum(1 for keyword in keywords if keyword in text)
