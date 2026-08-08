import json
from pathlib import Path

from cyberagent.models import ChallengeState
from cyberagent.report import render_report


def save_state(state: ChallengeState, output_dir: str | Path) -> Path:
    """Save a challenge state as JSON and return the written path."""
    run_dir = _run_dir(state, output_dir)
    path = _write_state(state, run_dir)
    return path


def save_run_outputs(state: ChallengeState, output_dir: str | Path) -> dict[str, Path]:
    """Save all user-facing run artifacts and return their paths."""
    run_dir = _run_dir(state, output_dir)
    return {
        "state": _write_state(state, run_dir),
        "report": _write_report(state, run_dir),
        "flag": _write_flag(state, run_dir),
        "log": _write_run_log(state, run_dir),
    }


def load_state(challenge_id: str, output_dir: str | Path) -> ChallengeState | None:
    """Load a saved challenge state, returning None when it does not exist."""
    path = Path(output_dir) / challenge_id / "state.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _run_dir(state: ChallengeState, output_dir: str | Path) -> Path:
    challenge_id = state.get("challenge_id")
    if not challenge_id:
        raise ValueError("challenge_id is required to save run outputs")

    run_dir = Path(output_dir) / challenge_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _write_state(state: ChallengeState, run_dir: Path) -> Path:
    path = run_dir / "state.json"
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _write_report(state: ChallengeState, run_dir: Path) -> Path:
    path = run_dir / "report.md"
    path.write_text(render_report(state), encoding="utf-8")
    return path


def _write_flag(state: ChallengeState, run_dir: Path) -> Path:
    path = run_dir / "flag.txt"
    flag = state.get("final_flag", "")
    path.write_text(f"{flag}\n" if flag else "", encoding="utf-8")
    return path


def _write_run_log(state: ChallengeState, run_dir: Path) -> Path:
    path = run_dir / "run.log"
    path.write_text(_render_run_log(state), encoding="utf-8")
    return path


def _render_run_log(state: ChallengeState) -> str:
    lines: list[str] = []
    for event in state.get("trace", []):
        details = json.dumps(event.get("details", {}), ensure_ascii=False, sort_keys=True)
        lines.append(
            f"{event.get('ts', '')}\t"
            f"{event.get('node', '')}\t"
            f"{event.get('event', '')}\t"
            f"{details}"
        )
    return "\n".join(lines) + ("\n" if lines else "")
