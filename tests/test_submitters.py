import pytest

from cyberagent.submitters.disabled import DisabledSubmitProvider
from cyberagent.submitters.http_json import HttpJsonSubmitProvider
from cyberagent.submitters.registry import get_submit_provider


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self._body


def test_disabled_submit_provider_returns_skip_result():
    result = DisabledSubmitProvider().submit("1", "flag{demo}")

    assert result["submitted"] is False
    assert result["accepted"] is None
    assert result["status"] == "disabled"


def test_submit_registry_defaults_to_disabled(monkeypatch):
    monkeypatch.delenv("FLAG_SUBMIT_PROVIDER", raising=False)

    assert get_submit_provider().name == "disabled"


def test_submit_registry_rejects_unknown_provider(monkeypatch):
    monkeypatch.setenv("FLAG_SUBMIT_PROVIDER", "missing")

    with pytest.raises(ValueError):
        get_submit_provider()


def test_http_json_submit_provider_posts_flag_and_parses_acceptance(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["body"] = request.data
        captured["auth"] = request.headers["Authorization"]
        captured["timeout"] = timeout
        return FakeResponse(b'{"correct": true, "message": "accepted"}')

    monkeypatch.setenv("FLAG_SUBMIT_API_BASE_URL", "https://ctf.example/api")
    monkeypatch.setenv("FLAG_SUBMIT_PATH_TEMPLATE", "/tasks/{challenge_id}/submit")
    monkeypatch.setenv("FLAG_SUBMIT_TOKEN", "token-value")
    monkeypatch.setenv("FLAG_SUBMIT_TIMEOUT", "7")
    monkeypatch.setattr("cyberagent.submitters.http_json.urlopen", fake_urlopen)

    result = HttpJsonSubmitProvider().submit("web01", "flag{demo}")

    assert captured["url"] == "https://ctf.example/api/tasks/web01/submit"
    assert captured["method"] == "POST"
    assert captured["body"] == b'{"flag": "flag{demo}"}'
    assert captured["auth"] == "Bearer token-value"
    assert captured["timeout"] == 7
    assert result["submitted"] is True
    assert result["accepted"] is True
    assert result["message"] == "accepted"


def test_http_json_submit_provider_parses_rejection(monkeypatch):
    def fake_urlopen(request, timeout):
        return FakeResponse(b'{"success": false, "detail": "wrong flag"}')

    monkeypatch.setenv("FLAG_SUBMIT_API_BASE_URL", "https://ctf.example/api")
    monkeypatch.setattr("cyberagent.submitters.http_json.urlopen", fake_urlopen)

    result = HttpJsonSubmitProvider().submit("web01", "flag{wrong}")

    assert result["submitted"] is True
    assert result["accepted"] is False
    assert result["status"] == "rejected"
    assert result["message"] == "wrong flag"
