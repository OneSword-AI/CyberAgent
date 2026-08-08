from dotenv import load_dotenv

from cyberagent.checkpoint import save_run_outputs
from cyberagent.graph import build_graph, initial_state
from cyberagent.models import ChallengeState


def run_challenge(
    challenge_id: str,
    *,
    load_env: bool = True,
    save: bool = False,
    output_dir: str = "runs",
) -> ChallengeState:
    """Run the CyberAgent graph for one challenge and return the final state."""
    if load_env:
        load_dotenv()

    app = build_graph()
    result = app.invoke(initial_state(challenge_id))
    if save:
        save_run_outputs(result, output_dir)
    return result
