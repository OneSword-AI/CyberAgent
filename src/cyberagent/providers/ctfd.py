import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cyberagent.models import ChallengeState


def fetch_challenge(state: ChallengeState) -> ChallengeState:
    """Fetch challenge metadata from a CTFd-compatible HTTP API."""
    challenge_id = state.get("challenge_id")
    if not challenge_id:
        raise ValueError("challenge_id is required to fetch challenge metadata")

    base_url = os.environ["CTF_API_BASE_URL"].rstrip("/")
    path_template = os.getenv("CTF_API_CHALLENGE_PATH_TEMPLATE", "/challenges/{challenge_id}")
    url = f"{base_url}{path_template.format(challenge_id=challenge_id)}"

    data = _request_json(url)
    challenge = _unwrap_payload(data)

    return {
        **state,
        "title": _first_text(challenge, "title", "name"),
        "description": _first_text(challenge, "description", "body"),
        "category_hint": _optional_text(challenge.get("category")),
        "attachments": _extract_attachments(challenge),
        "remote_targets": _extract_remote_targets(challenge),
    }


def _request_json(url: str) -> dict[str, Any]:
    headers = {"Accept": "application/json"}

    token = os.getenv("CTF_API_TOKEN")
    if token:
        auth_scheme = os.getenv("CTF_API_AUTH_SCHEME", "Token")
        headers["Authorization"] = f"{auth_scheme} {token}"

    request = Request(url, headers=headers)

    try:
        with urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"challenge API returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"failed to connect to challenge API: {exc.reason}") from exc


def _unwrap_payload(data: dict[str, Any]) -> dict[str, Any]:
    payload = data.get("data", data)
    if not isinstance(payload, dict):
        raise ValueError("challenge API response must be a JSON object")
    return payload


def _first_text(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str):
            return value
    return ""


def _optional_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        name = value.get("name")
        return name if isinstance(name, str) else None
    return None


def _extract_attachments(data: dict[str, Any]) -> list[str]:
    files = data.get("files") or data.get("attachments") or []
    if not isinstance(files, list):
        return []

    attachments: list[str] = []
    for item in files:
        if isinstance(item, str):
            attachments.append(item)
        elif isinstance(item, dict):
            value = item.get("url") or item.get("href") or item.get("name")
            if isinstance(value, str):
                attachments.append(value)
    return attachments


def _extract_remote_targets(data: dict[str, Any]) -> list[str]:
    targets: list[str] = []

    for key in ("connection_info", "remote", "target", "url"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            targets.append(value.strip())

    services = data.get("services") or data.get("targets") or []
    if isinstance(services, list):
        for item in services:
            if isinstance(item, str):
                targets.append(item)
            elif isinstance(item, dict):
                host = item.get("host")
                port = item.get("port")
                if isinstance(host, str) and port:
                    targets.append(f"{host}:{port}")

    return list(dict.fromkeys(targets))
