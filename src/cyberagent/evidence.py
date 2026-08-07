from typing import Any, Literal, NotRequired, TypedDict

from cyberagent.models import ChallengeState


FindingKind = Literal["finding", "evidence", "hypothesis"]


class Finding(TypedDict):
    kind: FindingKind
    agent: str
    summary: str
    evidence: dict[str, Any]
    error: NotRequired[str]


def make_finding(
    *,
    agent: str,
    summary: str,
    evidence: dict[str, Any] | None = None,
    kind: FindingKind = "finding",
    error: str | None = None,
) -> Finding:
    finding: Finding = {
        "kind": kind,
        "agent": agent,
        "summary": summary,
        "evidence": evidence or {},
    }
    if error is not None:
        finding["error"] = error
    return finding


def add_finding(
    state: ChallengeState,
    *,
    agent: str,
    summary: str,
    evidence: dict[str, Any] | None = None,
    kind: FindingKind = "finding",
    error: str | None = None,
) -> ChallengeState:
    return {
        **state,
        "findings": [
            *state.get("findings", []),
            make_finding(
                agent=agent,
                summary=summary,
                evidence=evidence,
                kind=kind,
                error=error,
            ),
        ],
    }


def add_evidence(
    state: ChallengeState,
    *,
    agent: str,
    summary: str,
    evidence: dict[str, Any] | None = None,
) -> ChallengeState:
    return add_finding(
        state,
        agent=agent,
        summary=summary,
        evidence=evidence,
        kind="evidence",
    )


def add_hypothesis(
    state: ChallengeState,
    *,
    agent: str,
    summary: str,
    evidence: dict[str, Any] | None = None,
) -> ChallengeState:
    return add_finding(
        state,
        agent=agent,
        summary=summary,
        evidence=evidence,
        kind="hypothesis",
    )
