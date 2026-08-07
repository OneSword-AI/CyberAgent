import json
from pathlib import Path

from cyberagent.models import ChallengeState


def save_state(state: ChallengeState, output_dir: str | Path) -> Path:
    """Save a challenge state as JSON and return the written path."""
    challenge_id = state.get("challenge_id")
    if not challenge_id:
        raise ValueError("challenge_id is required to save state")

    run_dir = Path(output_dir) / challenge_id
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "state.json"
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load_state(challenge_id: str, output_dir: str | Path) -> ChallengeState | None:
    """Load a saved challenge state, returning None when it does not exist."""
    path = Path(output_dir) / challenge_id / "state.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
