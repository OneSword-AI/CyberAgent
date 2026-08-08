import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cyberagent.submitters.base import SubmitResult

ACCEPTED_KEYS = ("accepted", "correct", "success", "valid")
MESSAGE_KEYS = ("message", "detail", "error")


class HttpJsonSubmitProvider:
    name = "http_json"

    def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        base_url = os.environ["FLAG_SUBMIT_API_BASE_URL"].rstrip("/")
        path_template = os.getenv("FLAG_SUBMIT_PATH_TEMPLATE", "/challenges/{challenge_id}/submit")
        url = f"{base_url}{path_template.format(challenge_id=challenge_id)}"
        payload = json.dumps({"flag": flag}).encode("utf-8")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        token = os.getenv("FLAG_SUBMIT_TOKEN")
        if token:
            auth_scheme = os.getenv("FLAG_SUBMIT_AUTH_SCHEME", "Bearer")
            headers["Authorization"] = f"{auth_scheme} {token}"

        request = Request(url, data=payload, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=_timeout()) as response:
                raw = _read_json_response(response.read())
        except HTTPError as exc:
            raw = _read_json_response(exc.read())
            return {
                "submitted": True,
                "accepted": False,
                "status": f"http_{exc.code}",
                "message": _message(raw) or f"flag submit API returned HTTP {exc.code}",
                "raw_response": raw,
            }
        except URLError as exc:
            return {
                "submitted": True,
                "accepted": False,
                "status": "connection_error",
                "message": f"failed to connect to flag submit API: {exc.reason}",
                "raw_response": None,
            }

        accepted = _accepted(raw)
        return {
            "submitted": True,
            "accepted": accepted,
            "status": "accepted" if accepted else "rejected",
            "message": _message(raw) or ("accepted" if accepted else "rejected"),
            "raw_response": raw,
        }


def _accepted(raw: dict[str, Any]) -> bool:
    for key in ACCEPTED_KEYS:
        value = raw.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "yes", "ok", "accepted", "correct", "success", "valid"}:
                return True
            if normalized in {"false", "no", "rejected", "incorrect", "invalid", "wrong"}:
                return False
    return False


def _message(raw: dict[str, Any]) -> str:
    for key in MESSAGE_KEYS:
        value = raw.get(key)
        if value is not None:
            return str(value)
    return ""


def _read_json_response(body: bytes) -> dict[str, Any]:
    if not body:
        return {}
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise TypeError("flag submit API response must be a JSON object")
    return data


def _timeout() -> float:
    return float(os.getenv("FLAG_SUBMIT_TIMEOUT", "20"))
