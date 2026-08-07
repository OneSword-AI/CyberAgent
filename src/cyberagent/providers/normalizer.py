from typing import Any

from cyberagent.providers.base import ChallengeData


def normalize_challenge(raw: dict[str, Any]) -> ChallengeData:
    """Normalize unknown challenge payloads into CyberAgent's internal shape."""
    payload = _unwrap_payload(raw)

    return {
        "title": _first_text(payload, "title", "name", "subject"),
        "description": _first_text(payload, "description", "body", "content", "text", "prompt"),
        "category_hint": _optional_text(_first_value(payload, "category", "type", "tag")),
        "flag_format": _optional_text(_first_value(payload, "flag_format", "flagFormat")),
        "attachments": _extract_attachments(payload),
        "remote_targets": _extract_remote_targets(payload),
        "raw": raw,
    }


def _unwrap_payload(raw: dict[str, Any]) -> dict[str, Any]:
    for key in ("challenge", "data", "result", "payload"):
        value = raw.get(key)
        if isinstance(value, dict):
            return value
    return raw


def _first_value(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return None


def _first_text(data: dict[str, Any], *keys: str) -> str:
    value = _first_value(data, *keys)
    return value.strip() if isinstance(value, str) else ""


def _optional_text(value: Any) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    if isinstance(value, dict):
        for key in ("name", "title", "value"):
            nested = value.get(key)
            if isinstance(nested, str) and nested.strip():
                return nested.strip()
    return None


def _extract_attachments(data: dict[str, Any]) -> list[str]:
    values = _collect_lists(data, "attachments", "files", "file_urls", "downloads")
    attachments: list[str] = []

    for item in values:
        if isinstance(item, str):
            attachments.append(item)
        elif isinstance(item, dict):
            value = _first_text(item, "url", "href", "path", "name", "filename")
            if value:
                attachments.append(value)

    return _unique(attachments)


def _extract_remote_targets(data: dict[str, Any]) -> list[str]:
    targets: list[str] = []

    for key in ("connection_info", "remote", "target", "url", "endpoint", "service"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            targets.append(value.strip())

    for item in _collect_lists(data, "remote_targets", "targets", "services", "endpoints"):
        if isinstance(item, str):
            targets.append(item)
        elif isinstance(item, dict):
            value = _target_from_mapping(item)
            if value:
                targets.append(value)

    return _unique(targets)


def _target_from_mapping(data: dict[str, Any]) -> str:
    url = _first_text(data, "url", "endpoint", "target", "remote")
    if url:
        return url

    host = _first_text(data, "host", "hostname", "ip")
    port = data.get("port")
    if host and port:
        return f"{host}:{port}"
    return host


def _collect_lists(data: dict[str, Any], *keys: str) -> list[Any]:
    values: list[Any] = []
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            values.extend(value)
        elif value:
            values.append(value)
    return values


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
