from pathlib import Path

from cyberagent.agents.skill_loader import load_skills_for_challenge
from cyberagent.graph import initial_state
from cyberagent.skills.loader import (
    load_challenge_skills,
    load_skill,
    render_specialist_skill_contexts,
    render_skill_context,
)


def test_load_skill_parses_frontmatter_and_body(tmp_path: Path):
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text(
        """---
name: ctf-test
description: Test skill description.
---

# Test Skill

Use this workflow.
""",
        encoding="utf-8",
    )

    skill = load_skill(skill_file)

    assert skill["name"] == "ctf-test"
    assert skill["description"] == "Test skill description."
    assert "# Test Skill" in skill["body"]
    assert skill["path"] == str(skill_file)


def test_load_challenge_skills_selects_web_from_remote_target():
    state = initial_state("skill-web")
    state["title"] = "入口"
    state["description"] = "需要观察页面行为"
    state["remote_targets"] = ["https://web.test/"]

    skills = load_challenge_skills(state)

    assert [skill["name"] for skill in skills] == ["ctf-web"]


def test_load_challenge_skills_selects_attachment_related_skills():
    state = initial_state("skill-apk")
    state["attachments"] = ["challenge.apk"]

    skills = load_challenge_skills(state)

    assert [skill["name"] for skill in skills] == ["ctf-mobile", "ctf-reverse"]


def test_render_skill_context_includes_description_and_body():
    context = render_skill_context(
        [
            {
                "name": "ctf-web",
                "description": "Web workflow.",
                "body": "# CTF Web\n\nWorkflow body.",
                "path": "skills/ctf-web/SKILL.md",
            }
        ]
    )

    assert "## ctf-web" in context
    assert "Description: Web workflow." in context
    assert "Workflow body." in context


def test_render_specialist_skill_contexts_filters_by_agent():
    contexts = render_specialist_skill_contexts(
        [
            {
                "name": "ctf-web",
                "description": "Web workflow.",
                "body": "# CTF Web\n\nProbe HTTP.",
                "path": "skills/ctf-web/SKILL.md",
            },
            {
                "name": "ctf-crypto",
                "description": "Crypto workflow.",
                "body": "# CTF Crypto\n\nAnalyze RSA.",
                "path": "skills/ctf-crypto/SKILL.md",
            },
        ]
    )

    assert "ctf-web" in contexts["web_agent"]
    assert "ctf-crypto" not in contexts["web_agent"]
    assert "ctf-crypto" in contexts["crypto_agent"]


def test_skill_loader_node_writes_state_and_finding():
    state = initial_state("skill-node")
    state["remote_targets"] = ["https://web.test/"]

    result = load_skills_for_challenge(state)

    assert result["loaded_skills"][0]["name"] == "ctf-web"
    assert "ctf-web" in result["skill_context"]
    assert "ctf-web" in result["specialist_skill_contexts"]["web_agent"]
    assert result["findings"][-1]["agent"] == "skill_loader"
    assert result["trace"][-1]["event"] == "skills.load"
