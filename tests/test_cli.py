import json

import cyberagent


def test_main_passes_save_options_to_runtime(monkeypatch, capsys):
    calls = []

    def fake_run_challenge(challenge_id, *, save, output_dir):
        calls.append(
            {
                "challenge_id": challenge_id,
                "save": save,
                "output_dir": output_dir,
            }
        )
        return {"challenge_id": challenge_id, "candidate_flags": []}

    monkeypatch.setattr(cyberagent, "run_challenge", fake_run_challenge)
    monkeypatch.setattr(
        "sys.argv",
        ["cyberagent", "web01", "--save", "--output-dir", "artifacts"],
    )

    cyberagent.main()

    assert calls == [
        {
            "challenge_id": "web01",
            "save": True,
            "output_dir": "artifacts",
        }
    ]
    assert json.loads(capsys.readouterr().out)["challenge_id"] == "web01"


def test_main_uses_default_save_options(monkeypatch):
    calls = []

    def fake_run_challenge(challenge_id, *, save, output_dir):
        calls.append(
            {
                "challenge_id": challenge_id,
                "save": save,
                "output_dir": output_dir,
            }
        )
        return {"challenge_id": challenge_id, "candidate_flags": []}

    monkeypatch.setattr(cyberagent, "run_challenge", fake_run_challenge)
    monkeypatch.setattr("sys.argv", ["cyberagent", "web01"])

    cyberagent.main()

    assert calls == [
        {
            "challenge_id": "web01",
            "save": False,
            "output_dir": "runs",
        }
    ]
