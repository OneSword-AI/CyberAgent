from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from cyberagent.tools.models import ToolResult


DEFAULT_HEADERS = {"User-Agent": "CyberAgent/0.1"}
SUPPORTED_SCHEMES = {"http", "https"}


def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
    max_chars: int = 2000,
) -> ToolResult:
    """Perform a bounded HTTP/HTTPS GET."""
    return http_request(
        "GET",
        url,
        headers=headers,
        timeout=timeout,
        max_chars=max_chars,
    )


def http_post(
    url: str,
    *,
    data: bytes | str | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
    max_chars: int = 2000,
) -> ToolResult:
    """Perform a bounded HTTP/HTTPS POST."""
    return http_request(
        "POST",
        url,
        data=data,
        headers=headers,
        timeout=timeout,
        max_chars=max_chars,
    )


def http_request(
    method: str,
    url: str,
    *,
    data: bytes | str | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
    max_chars: int = 2000,
) -> ToolResult:
    """Perform a bounded HTTP/HTTPS request and return a normalized result."""
    method = method.upper()
    parsed = urlparse(url)
    validation_error = _validate_url(parsed)
    if validation_error:
        return _error_result(method, url, validation_error, scheme=parsed.scheme)

    body = _encode_body(data)
    request = Request(
        url,
        data=body,
        headers={**DEFAULT_HEADERS, **(headers or {})},
        method=method,
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            output, truncated = _read_text(response, max_chars)
            status = getattr(response, "status", None)
            response_headers = dict(getattr(response, "headers", {}) or {})
    except HTTPError as exc:
        output = exc.read(max_chars).decode("utf-8", errors="replace")
        return {
            "tool": _tool_name(method),
            "ok": False,
            "output": output,
            "error": f"HTTP {exc.code}",
            "exit_code": exc.code,
            "metadata": {
                "method": method,
                "url": url,
                "scheme": parsed.scheme,
                "status": exc.code,
                "headers": dict(exc.headers or {}),
                "truncated": False,
            },
        }
    except URLError as exc:
        return _error_result(method, url, f"URL error: {exc.reason}", scheme=parsed.scheme)
    except Exception as exc:
        return _error_result(method, url, str(exc), scheme=parsed.scheme)

    return {
        "tool": _tool_name(method),
        "ok": True,
        "output": output,
        "error": None,
        "exit_code": 0,
        "metadata": {
            "method": method,
            "url": url,
            "scheme": parsed.scheme,
            "status": status,
            "headers": response_headers,
            "truncated": truncated,
        },
    }


def _validate_url(parsed) -> str | None:
    if parsed.scheme not in SUPPORTED_SCHEMES:
        return f"unsupported URL scheme: {parsed.scheme or '<empty>'}"
    if not parsed.netloc:
        return "missing URL host"
    return None


def _encode_body(data: bytes | str | None) -> bytes | None:
    if data is None:
        return None
    if isinstance(data, bytes):
        return data
    return data.encode("utf-8")


def _read_text(response, max_chars: int) -> tuple[str, bool]:
    body = response.read(max_chars + 1)
    return body[:max_chars].decode("utf-8", errors="replace"), len(body) > max_chars


def _tool_name(method: str) -> str:
    return f"http_{method.lower()}"


def _error_result(method: str, url: str, error: str, *, scheme: str = "") -> ToolResult:
    return {
        "tool": _tool_name(method),
        "ok": False,
        "output": "",
        "error": error,
        "exit_code": None,
        "metadata": {
            "method": method,
            "url": url,
            "scheme": scheme,
        },
    }
