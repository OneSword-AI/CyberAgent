import json

from cyberagent.graph import initial_state
from cyberagent.providers.fetch import fetch_challenge
from cyberagent.providers.normalizer import normalize_challenge


def test_normalize_plain_challenge_payload():
    raw = {
        "name": "easy web",
        "body": "Find the SQL injection.",
        "type": "Web",
        "flagFormat": "flag{.*}",
        "files": [{"url": "https://example.test/attachment.zip"}],
        "services": [{"host": "web.example.test", "port": 8080}],
    }

    challenge = normalize_challenge(raw)

    assert challenge["title"] == "easy web"
    assert challenge["description"] == "Find the SQL injection."
    assert challenge["category_hint"] == "Web"
    assert challenge["flag_format"] == "flag{.*}"
    assert challenge["attachments"] == ["https://example.test/attachment.zip"]
    assert challenge["remote_targets"] == ["web.example.test:8080"]
    assert challenge["raw"] == raw


def test_normalize_nested_challenge_payload():
    raw = {
        "payload": {
            "subject": "rsa warmup",
            "prompt": "Recover plaintext from weak RSA parameters.",
            "tag": {"name": "Crypto"},
            "downloads": ["rsa.txt"],
            "remote_targets": ["nc crypto.example.test 31337"],
        }
    }

    challenge = normalize_challenge(raw)

    assert challenge["title"] == "rsa warmup"
    assert challenge["description"] == "Recover plaintext from weak RSA parameters."
    assert challenge["category_hint"] == "Crypto"
    assert challenge["attachments"] == ["rsa.txt"]
    assert challenge["remote_targets"] == ["nc crypto.example.test 31337"]


def test_fetch_challenge_uses_selected_provider_and_updates_state(tmp_path, monkeypatch):
    challenge_dir = tmp_path / "challenges"
    challenge_dir.mkdir()
    challenge_file = challenge_dir / "123.json"
    challenge_file.write_text(
        json.dumps(
            {
                "challenge": {
                    "title": "reverse me",
                    "description": "Analyze this binary license check.",
                    "category": "Reverse",
                    "attachments": [{"filename": "rev.bin"}],
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("CHALLENGE_PROVIDER", "local_json")
    monkeypatch.setenv("CHALLENGE_LOCAL_JSON_DIR", str(challenge_dir))

    state = fetch_challenge(initial_state("123"))

    assert state["provider_name"] == "local_json"
    assert state["title"] == "reverse me"
    assert state["description"] == "Analyze this binary license check."
    assert state["category_hint"] == "Reverse"
    assert state["attachments"] == ["rev.bin"]
    assert state["remote_targets"] == []
    assert state["raw_challenge"]["challenge"]["title"] == "reverse me"
