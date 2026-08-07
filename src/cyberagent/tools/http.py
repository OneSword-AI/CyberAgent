from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from cyberagent.tools.models import ToolResult


def http_get(url: str, *, timeout: float = 10, max_chars: int = 2000) -> ToolResult:
    """Perform a bounded HTTP GET and return a normalized tool result."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return _error_result(url, f"unsupported URL scheme: {parsed.scheme or '<empty>'}")

    request = Request(url, headers={"User-Agent": "CyberAgent/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(max_chars + 1)
            text = body[:max_chars].decode("utf-8", errors="replace")
            truncated = len(body) > max_chars
            status = getattr(response, "status", None)
            headers = dict(getattr(response, "headers", {}) or {})
    except HTTPError as exc:
        body = exc.read(max_chars).decode("utf-8", errors="replace")
        return {
            "tool": "http_get",
            "ok": False,
            "output": body,
            "error": f"HTTP {exc.code}",
            "exit_code": exc.code,
            "metadata": {"url": url, "status": exc.code},
        }
    except URLError as exc:
        return _error_result(url, f"URL error: {exc.reason}")
    except Exception as exc:
        return _error_result(url, str(exc))

    return {
        "tool": "http_get",
        "ok": True,
        "output": text,
        "error": None,
        "exit_code": 0,
        "metadata": {
            "url": url,
            "status": status,
            "headers": headers,
            "truncated": truncated,
        },
    }


def _error_result(url: str, error: str) -> ToolResult:
    return {
        "tool": "http_get",
        "ok": False,
        "output": "",
        "error": error,
        "exit_code": None,
        "metadata": {"url": url},
    }
