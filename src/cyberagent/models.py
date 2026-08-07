from typing import Any, NotRequired, TypedDict


class ChallengeState(TypedDict):
    # The initial state can start with only challenge_id. These fields are
    # populated by the challenge provider.
    title: NotRequired[str]
    description: NotRequired[str]

    attachments: list[str]
    remote_targets: list[str]
    predicted_categories: list[str]
    next_agents: list[str]
    active_agents: list[str]
    candidate_flags: list[str]
    findings: list[dict]
    failed_attempts: list[dict]
    tool_outputs: list[dict]
    trace: list[dict]

    challenge_id: NotRequired[str]
    provider_name: NotRequired[str]
    raw_challenge: NotRequired[dict[str, Any]]
    flag_format: NotRequired[str]
    category_hint: NotRequired[str]
    complexity: NotRequired[str]
    reasoning_summary: NotRequired[str]
    final_flag: NotRequired[str]
    report: NotRequired[str]
