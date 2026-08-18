from typing import Annotated, Any, Literal, NotRequired, TypedDict


def _append_list(left: list, right: list) -> list:
    return [*left, *right]


def _last(_left: Any, right: Any) -> Any:
    return right


def _merge_unique(left: list, right: list) -> list:
    return list(dict.fromkeys([*left, *right]))


class SpecialistResult(TypedDict):
    """Normalized result returned by every specialist Agent."""

    agent: str
    status: Literal["completed", "skipped", "failed"]
    summary: str
    findings: list[dict[str, Any]]
    candidate_flags: list[str]
    tool_outputs: list[dict[str, Any]]
    next_actions: list[dict[str, Any]]
    error: NotRequired[str]


class ChallengeState(TypedDict):
    # The initial state can start with only challenge_id. These fields are
    # populated by the challenge provider.
    title: NotRequired[str]
    description: NotRequired[str]

    attachments: Annotated[list[str], _last]
    downloaded_attachments: Annotated[list[dict], _append_list]
    remote_targets: Annotated[list[str], _last]
    predicted_categories: Annotated[list[str], _last]
    next_agents: Annotated[list[str], _last]
    active_agents: Annotated[list[str], _last]
    plan: Annotated[str, _last]
    plan_rationale: Annotated[str, _last]
    controller_decisions: Annotated[dict[str, Any], _last]
    loaded_skills: Annotated[list[dict[str, Any]], _last]
    skill_context: Annotated[str, _last]
    controller_round: Annotated[int, _last]
    max_controller_rounds: Annotated[int, _last]
    budget: Annotated[dict[str, Any], _last]
    budget_usage: Annotated[dict[str, Any], _last]
    budget_exhausted: Annotated[bool, _last]
    stop_condition: Annotated[str, _last]
    candidate_flags: Annotated[list[str], _merge_unique]
    candidate_flag_records: Annotated[list[dict[str, Any]], _append_list]
    specialist_results: Annotated[list[SpecialistResult], _append_list]
    published_specialist_results: Annotated[int, _last]
    findings: Annotated[list[dict], _append_list]
    verification_results: Annotated[list[dict], _append_list]
    submit_results: Annotated[list[dict], _append_list]
    failed_attempts: Annotated[list[dict], _append_list]
    tool_outputs: Annotated[list[dict], _append_list]
    trace: Annotated[list[dict], _append_list]
    signals: Annotated[list[dict], _last]
    retry_count: Annotated[int, _last]
    max_retries: Annotated[int, _last]
    evidence_gate_passed: Annotated[bool, _last]

    challenge_id: NotRequired[str]
    artifacts_dir: NotRequired[str]
    skills_dir: NotRequired[str]
    provider_name: NotRequired[str]
    raw_challenge: NotRequired[dict[str, Any]]
    flag_format: NotRequired[str]
    category_hint: NotRequired[str]
    complexity: NotRequired[str]
    reasoning_summary: NotRequired[str]
    final_flag: NotRequired[str]
    remote_accepted_flag: NotRequired[str]
    report: NotRequired[str]
