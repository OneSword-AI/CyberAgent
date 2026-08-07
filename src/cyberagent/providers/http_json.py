import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class HttpJsonProvider:
    name = "http_json"

    def fetch(self, challenge_id: str) -> dict[str, Any]:
        base_url = os.environ["CHALLENGE_API_BASE_URL"].rstrip("/")
        path_template = os.getenv("CHALLENGE_API_PATH_TEMPLATE", "/challenges/{challenge_id}")
        url = f"{base_url}{path_template.format(challenge_id=challenge_id)}"

        headers = {"Accept": "application/json"}
        token = os.getenv("CHALLENGE_API_TOKEN")
        if token:
            auth_scheme = os.getenv("CHALLENGE_API_AUTH_SCHEME", "Bearer")
            headers["Authorization"] = f"{auth_scheme} {token}"

        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=_timeout()) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"challenge API returned HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"failed to connect to challenge API: {exc.reason}") from exc

        if not isinstance(payload, dict):
            raise ValueError("challenge API response must be a JSON object")
        return payload


def _timeout() -> float:
    return float(os.getenv("CHALLENGE_API_TIMEOUT", "20"))
