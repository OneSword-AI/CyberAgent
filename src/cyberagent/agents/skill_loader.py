from pathlib import Path

from cyberagent.evidence import add_finding
from cyberagent.models import ChallengeState
from cyberagent.skills.loader import load_challenge_skills, render_skill_context
from cyberagent.trace import add_trace_event


def load_skills_for_challenge(state: ChallengeState) -> ChallengeState:
    """Load relevant CTF skills into the graph state."""
    skills_dir = state.get("skills_dir")
    skills = load_challenge_skills(
        state,
        skills_dir=Path(skills_dir) if skills_dir else None,
    )
    loaded_skills = [
        {
            "name": skill["name"],
            "description": skill["description"],
            "path": skill["path"],
        }
        for skill in skills
    ]
    next_state: ChallengeState = {
        **state,
        "loaded_skills": loaded_skills,
        "skill_context": render_skill_context(skills),
    }
    next_state = add_trace_event(
        next_state,
        node="load_skills",
        event="skills.load",
        details={"loaded_skills": [skill["name"] for skill in skills]},
    )
    return add_finding(
        next_state,
        agent="skill_loader",
        summary=f"Loaded {len(skills)} CTF skill(s).",
        evidence={"loaded_skills": loaded_skills},
    )
