from cyberagent.agents.specialists import crypto_agent, misc_agent, web_agent
from cyberagent.agents.tool_adapters import (
    SpecialistToolAdapterRegistry,
    build_default_specialist_adapters,
)
from cyberagent.graph import initial_state


class FakeSpecialistAdapter:
    def __init__(self, name: str, summary: str) -> None:
        self.name = name
        self.summary = summary

    def describe(self) -> dict:
        return {"name": self.name, "description": self.summary}

    def execute(self, state: dict) -> dict:
        return {
            "summary": self.summary,
            "findings": [],
            "candidate_flags": [f"flag{{{self.name}}}"],
            "tool_outputs": [
                {
                    "caller": f"{self.name}_agent",
                    "tool": f"{self.name}_tool",
                    "ok": True,
                    "output": "adapter output",
                    "error": None,
                    "exit_code": 0,
                    "metadata": {},
                }
            ],
            "next_actions": [],
        }


def test_default_specialist_adapters_expose_web_crypto_and_misc():
    registry = build_default_specialist_adapters()

    assert {item["name"] for item in registry.describe_all()} == {
        "web",
        "crypto",
        "misc",
    }


def test_specialists_can_use_replacement_adapters():
    registry = SpecialistToolAdapterRegistry(
        [
            FakeSpecialistAdapter("web", "custom web adapter"),
            FakeSpecialistAdapter("crypto", "custom crypto adapter"),
            FakeSpecialistAdapter("misc", "custom misc adapter"),
        ]
    )

    web_state = initial_state("web-adapter")
    web_state["active_agents"] = ["web_agent"]
    crypto_state = initial_state("crypto-adapter")
    crypto_state["active_agents"] = ["crypto_agent"]
    misc_state = initial_state("misc-adapter")
    misc_state["active_agents"] = ["misc_agent"]

    web_result = web_agent(web_state, adapters=registry)
    crypto_result = crypto_agent(crypto_state, adapters=registry)
    misc_result = misc_agent(misc_state, adapters=registry)

    assert web_result["summary"] == "custom web adapter"
    assert crypto_result["summary"] == "custom crypto adapter"
    assert misc_result["summary"] == "custom misc adapter"
    assert web_result["candidate_flags"] == ["flag{web}"]
    assert crypto_result["candidate_flags"] == ["flag{crypto}"]
    assert misc_result["candidate_flags"] == ["flag{misc}"]
