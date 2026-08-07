from cyberagent.agents.foundation import AnalystAgent, CriticAgent, MemoryAgent, ObserverAgent
from cyberagent.blackboard import Blackboard
from cyberagent.evidence_gate import evidence_gate_passes
from cyberagent.signals import make_signal


def test_foundation_agents_process_subscribed_signals():
    blackboard = Blackboard()
    blackboard.post(
        make_signal(
            type="challenge_input",
            challenge_id="fa01",
            source="test",
            payload={"title": "demo"},
            provenance="input",
        )
    )

    observations = ObserverAgent().process_pending(blackboard, challenge_id="fa01")
    hypotheses = AnalystAgent().process_pending(blackboard, challenge_id="fa01")
    critic_reports = CriticAgent().process_pending(blackboard, challenge_id="fa01")

    assert observations[0]["type"] == "observation"
    assert hypotheses[0]["type"] == "hypothesis"
    assert critic_reports[0]["type"] == "critic_report"


def test_memory_agent_outputs_prior_only():
    blackboard = Blackboard()
    blackboard.post(
        make_signal(
            type="challenge_input",
            challenge_id="fa01",
            source="test",
            payload={"title": "demo"},
            provenance="input",
        )
    )

    priors = MemoryAgent().process_pending(blackboard, challenge_id="fa01")

    assert priors[0]["type"] == "memory_prior"
    assert priors[0]["provenance"] == "memory_prior"


def test_evidence_gate_requires_direct_evidence_and_critic_approval():
    memory_prior = make_signal(
        type="memory_prior",
        challenge_id="gate01",
        source="memory",
        payload={"summary": "looks like prior"},
        provenance="memory_prior",
    )
    critic_report = make_signal(
        type="critic_report",
        challenge_id="gate01",
        source="critic",
        payload={"verdict": "approved"},
        provenance="critic",
    )
    direct_evidence = make_signal(
        type="evidence",
        challenge_id="gate01",
        source="web_agent",
        payload={"flag": "flag{demo}"},
        provenance="direct_tool",
    )

    assert evidence_gate_passes([memory_prior, critic_report]) is False
    assert evidence_gate_passes([direct_evidence]) is False
    assert evidence_gate_passes([direct_evidence, critic_report]) is True
