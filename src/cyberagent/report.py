from cyberagent.models import ChallengeState


def render_report(state: ChallengeState) -> str:
    """Render a Markdown report from the current challenge state."""
    sections = [
        "# CyberAgent Report",
        _challenge_section(state),
        _classification_section(state),
        _agents_section(state),
        _candidate_flags_section(state),
        _findings_section(state),
        _tool_outputs_section(state),
    ]
    return "\n\n".join(section for section in sections if section).rstrip() + "\n"


def _challenge_section(state: ChallengeState) -> str:
    lines = [
        "## Challenge",
        f"- ID: {state.get('challenge_id', '')}",
        f"- Title: {state.get('title', '')}",
        f"- Category Hint: {state.get('category_hint', '') or ''}",
        f"- Flag Format: {state.get('flag_format', '') or ''}",
    ]
    description = state.get("description", "")
    if description:
        lines.extend(["", "### Description", description])
    return "\n".join(lines)


def _classification_section(state: ChallengeState) -> str:
    return "\n".join(
        [
            "## Classification",
            f"- Predicted Categories: {_join(state.get('predicted_categories', []))}",
            f"- Complexity: {state.get('complexity', '') or ''}",
            f"- Reasoning: {state.get('reasoning_summary', '') or ''}",
        ]
    )


def _agents_section(state: ChallengeState) -> str:
    return "\n".join(
        [
            "## Agents",
            f"- Next Agents: {_join(state.get('next_agents', []))}",
            f"- Active Agents: {_join(state.get('active_agents', []))}",
        ]
    )


def _candidate_flags_section(state: ChallengeState) -> str:
    flags = state.get("candidate_flags", [])
    if not flags:
        return "## Candidate Flags\n\nNone."
    return "## Candidate Flags\n\n" + "\n".join(f"- `{flag}`" for flag in flags)


def _findings_section(state: ChallengeState) -> str:
    findings = state.get("findings", [])
    if not findings:
        return "## Findings\n\nNone."

    lines = ["## Findings"]
    for finding in findings:
        lines.append(
            f"- [{finding.get('kind', 'finding')}] "
            f"{finding.get('agent', '')}: {finding.get('summary', '')}"
        )
    return "\n".join(lines)


def _tool_outputs_section(state: ChallengeState) -> str:
    outputs = state.get("tool_outputs", [])
    if not outputs:
        return "## Tool Outputs\n\nNone."

    lines = ["## Tool Outputs"]
    for output in outputs:
        status = "ok" if output.get("ok") else "failed"
        lines.append(
            f"- {output.get('caller', '')} -> {output.get('tool', '')}: "
            f"{status} exit={output.get('exit_code')}"
        )
    return "\n".join(lines)


def _join(values: list[str]) -> str:
    return ", ".join(values) if values else ""
