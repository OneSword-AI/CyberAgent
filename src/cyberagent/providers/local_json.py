import json
import os
from pathlib import Path
from typing import Any


class LocalJsonProvider:
    name = "local_json"

    def fetch(self, challenge_id: str) -> dict[str, Any]:
        root = Path(os.environ["CHALLENGE_LOCAL_JSON_DIR"])
        path = root / f"{challenge_id}.json"

        with path.open("r", encoding="utf-8") as file:
            payload = json.load(file)

        if not isinstance(payload, dict):
            raise ValueError(f"local challenge file must contain a JSON object: {path}")
        return payload
