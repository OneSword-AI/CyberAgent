from io import BytesIO
from urllib.error import HTTPError, URLError

from cyberagent.tools.http import http_get, http_post


class FakeResponse:
    status = 200
    headers = {"Content-Type": "text/plain"}

    def __init__(self, body: bytes):
        self.body = BytesIO(body)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size: int = -1) -> bytes:
        return self.body.read(size)


def test_http_get_returns_response_metadata(monkeypatch):
    def fake_urlopen(request, timeout):
        assert request.full_url == "https://example.test"
        assert request.get_method() == "GET"
        assert request.headers["User-agent"] == "CyberAgent/0.1"
        assert timeout == 5
        return FakeResponse(b"hello")

    monkeypatch.setattr("cyberagent.tools.http.urlopen", fake_urlopen)

    result = http_get("https://example.test", timeout=5)

    assert result["tool"] == "http_get"
    assert result["ok"] is True
    assert result["output"] == "hello"
    assert result["error"] is None
    assert result["exit_code"] == 0
    assert result["metadata"]["method"] == "GET"
    assert result["metadata"]["scheme"] == "https"
    assert result["metadata"]["status"] == 200
    assert result["metadata"]["truncated"] is False


def test_http_get_truncates_output(monkeypatch):
    def fake_urlopen(request, timeout):
        return FakeResponse(b"abcdef")

    monkeypatch.setattr("cyberagent.tools.http.urlopen", fake_urlopen)

    result = http_get("http://example.test", max_chars=3)

    assert result["output"] == "abc"
    assert result["metadata"]["truncated"] is True


def test_http_get_rejects_unsupported_scheme():
    result = http_get("file:///etc/passwd")

    assert result["ok"] is False
    assert result["error"] == "unsupported URL scheme: file"


def test_http_get_rejects_missing_host():
    result = http_get("https:///missing-host")

    assert result["ok"] is False
    assert result["error"] == "missing URL host"


def test_http_get_handles_http_error(monkeypatch):
    def fake_urlopen(request, timeout):
        raise HTTPError(
            url=request.full_url,
            code=404,
            msg="not found",
            hdrs=None,
            fp=BytesIO(b"missing"),
        )

    monkeypatch.setattr("cyberagent.tools.http.urlopen", fake_urlopen)

    result = http_get("https://example.test/missing")

    assert result["ok"] is False
    assert result["output"] == "missing"
    assert result["error"] == "HTTP 404"
    assert result["exit_code"] == 404
    assert result["metadata"]["method"] == "GET"
    assert result["metadata"]["scheme"] == "https"


def test_http_get_handles_url_error(monkeypatch):
    def fake_urlopen(request, timeout):
        raise URLError("connection refused")

    monkeypatch.setattr("cyberagent.tools.http.urlopen", fake_urlopen)

    result = http_get("https://example.test")

    assert result["ok"] is False
    assert result["error"] == "URL error: connection refused"


def test_http_post_sends_encoded_body_and_headers(monkeypatch):
    def fake_urlopen(request, timeout):
        assert request.full_url == "https://example.test/login"
        assert request.get_method() == "POST"
        assert request.data == b"username=admin"
        assert request.headers["Content-type"] == "application/x-www-form-urlencoded"
        return FakeResponse(b"posted")

    monkeypatch.setattr("cyberagent.tools.http.urlopen", fake_urlopen)

    result = http_post(
        "https://example.test/login",
        data="username=admin",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert result["tool"] == "http_post"
    assert result["ok"] is True
    assert result["output"] == "posted"
    assert result["metadata"]["method"] == "POST"
    assert result["metadata"]["scheme"] == "https"
