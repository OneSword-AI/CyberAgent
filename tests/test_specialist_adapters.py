from cyberagent.agents.specialist_signals import publish_specialist_results
from cyberagent.agents.specialists import crypto_agent, misc_agent, web_agent
from cyberagent.agents.tool_adapters import (
    AttachmentAnalysisAdapter,
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

    descriptions = registry.describe_all()
    assert {item["name"] for item in descriptions} == {
        "web",
        "crypto",
        "misc",
    }
    misc_description = next(item for item in descriptions if item["name"] == "misc")
    assert {"file", "strings", "unzip_list"} <= set(misc_description["capabilities"])


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


def test_attachment_analysis_adapter_runs_basic_file_tools():
    calls = []

    def fake_tool_executor(name: str, request: dict, *, caller: str) -> dict:
        calls.append((name, request["command"], caller))
        output = "Zip archive data" if request["command"].startswith("file ") else "flag{inside_zip}"
        return {
            "tool": "shell",
            "ok": True,
            "output": output,
            "error": None,
            "exit_code": 0,
            "metadata": {"command": request["command"]},
        }

    state = initial_state("attachment-adapter")
    state["downloaded_attachments"] = [
        {
            "source": "archive.zip",
            "path": "/tmp/archive.zip",
            "ok": True,
            "error": None,
        }
    ]

    result = AttachmentAnalysisAdapter(tool_executor=fake_tool_executor).execute(state)

    commands = [command for _, command, _ in calls]
    assert commands == [
        "file -b /tmp/archive.zip",
        "strings -n 4 /tmp/archive.zip | head -200",
        "unzip -l /tmp/archive.zip",
    ]
    assert all(caller == "misc_agent" for _, _, caller in calls)
    assert result["summary"] == "Misc Adapter analyzed 1 downloaded attachment(s)."
    assert [output["metadata"]["analysis"] for output in result["tool_outputs"]] == [
        "file",
        "strings",
        "unzip_list",
    ]
    assert result["findings"][0]["summary"] == "Analyzed attachment archive.zip."


def test_misc_agent_attachment_results_publish_to_blackboard():
    def fake_tool_executor(name: str, request: dict, *, caller: str) -> dict:
        return {
            "tool": "shell",
            "ok": True,
            "output": "ASCII text",
            "error": None,
            "exit_code": 0,
            "metadata": {"command": request["command"]},
        }

    registry = SpecialistToolAdapterRegistry(
        [AttachmentAnalysisAdapter(tool_executor=fake_tool_executor)]
    )
    state = initial_state("attachment-signal")
    state["active_agents"] = ["misc_agent"]
    state["downloaded_attachments"] = [
        {
            "source": "note.txt",
            "path": "/tmp/note.txt",
            "ok": True,
            "error": None,
        }
    ]

    state["specialist_results"] = [misc_agent(state, adapters=registry)]
    result = publish_specialist_results(state)

    signal = result["signals"][-1]
    assert signal["type"] == "specialist_result"
    assert signal["source"] == "misc_agent"
    assert signal["recipients"] == ["controller_agent"]
    assert signal["payload"]["tool_outputs"][0]["metadata"]["analysis"] == "file"
