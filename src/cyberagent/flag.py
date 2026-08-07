import re


DEFAULT_FLAG_PATTERN = re.compile(r"[A-Za-z0-9_]{2,32}\{[^{}\s]{1,200}\}")


def extract_flags(text: str, flag_format: str | None = None) -> list[str]:
    """Extract candidate flags from text."""
    if not text:
        return []

    if flag_format:
        matches = re.findall(flag_format, text)
        return dedupe_flags(_normalize_matches(matches))

    return dedupe_flags(DEFAULT_FLAG_PATTERN.findall(text))


def dedupe_flags(flags: list[str]) -> list[str]:
    """Deduplicate flags while preserving order."""
    result: list[str] = []
    seen: set[str] = set()
    for flag in flags:
        if flag not in seen:
            result.append(flag)
            seen.add(flag)
    return result


def merge_candidate_flags(existing: list[str], discovered: list[str]) -> list[str]:
    """Merge newly discovered flags into an existing candidate list."""
    return dedupe_flags([*existing, *discovered])


def _normalize_matches(matches) -> list[str]:
    normalized: list[str] = []
    for match in matches:
        if isinstance(match, tuple):
            normalized.append("".join(str(part) for part in match))
        else:
            normalized.append(str(match))
    return normalized
