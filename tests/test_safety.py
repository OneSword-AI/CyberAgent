from cyberagent.safety import L0SafetyGate


def test_l0_safety_gate_allows_known_action():
    decision = L0SafetyGate().evaluate(
        action_type="http.request",
        caller="web_agent",
        params={"url": "https://example.test"},
    )

    assert decision.allow is True


def test_l0_safety_gate_denies_unknown_action():
    decision = L0SafetyGate().evaluate(action_type="unknown", caller="agent")

    assert decision.allow is False
    assert decision.reason == "unknown action type"


def test_l0_safety_gate_denies_credential_reference():
    decision = L0SafetyGate().evaluate(
        action_type="shell.run",
        caller="agent",
        params={"command": "echo $OPENAI_API_KEY"},
    )

    assert decision.allow is False
    assert decision.reason == "action references protected credentials"
