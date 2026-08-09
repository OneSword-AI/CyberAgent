from cyberagent.agents.specialist_signals import publish_specialist_results
from cyberagent.agents.specialists import crypto_agent, misc_agent, web_agent
from cyberagent.agents.tool_adapters import (
    AttachmentAnalysisAdapter,
    SpecialistToolAdapterRegistry,
    WebToolAdapter,
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
    web_description = next(item for item in descriptions if item["name"] == "web")
    assert {"path_probe", "flag_extract", "form_detect", "parameter_detect"} <= set(
        web_description["capabilities"]
    )
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


def test_attachment_analysis_adapter_stops_shell_when_budget_is_exhausted():
    calls = []

    def fake_tool_executor(name: str, request: dict, *, caller: str) -> dict:
        calls.append(request["command"])
        return {
            "tool": "shell",
            "ok": True,
            "output": "ASCII text",
            "error": None,
            "exit_code": 0,
            "metadata": {"command": request["command"]},
        }

    state = initial_state("attachment-budget")
    state["budget"] = {**state["budget"], "max_shell_commands": 1}
    state["downloaded_attachments"] = [
        {
            "source": "note.txt",
            "path": "/tmp/note.txt",
            "ok": True,
            "error": None,
        }
    ]

    result = AttachmentAnalysisAdapter(tool_executor=fake_tool_executor).execute(state)

    assert calls == ["file -b /tmp/note.txt"]
    assert result["tool_outputs"][1]["metadata"]["budget_denied"] is True
    assert result["tool_outputs"][1]["tool"] == "shell"


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


def test_web_adapter_probes_paths_and_extracts_response_signals():
    calls = []

    def fake_tool_executor(name: str, request: dict, *, caller: str) -> dict:
        calls.append((name, request["url"], caller))
        body = ""
        if request["url"] == "http://web.test/":
            body = """
            <form method="post" action="/login">
              <input name="username">
              <input name="password">
            </form>
            <a href="/item?id=1&debug=true">item</a>
            """
        if request["url"].endswith("/robots.txt"):
            body = "flag{web_adapter}"
        return {
            "tool": "http_get",
            "ok": True,
            "output": body,
            "error": None,
            "exit_code": 0,
            "metadata": {"url": request["url"]},
        }

    state = initial_state("web-probe")
    state["remote_targets"] = ["http://web.test/"]

    result = WebToolAdapter(tool_executor=fake_tool_executor).execute(state)

    assert [url for _, url, _ in calls[:5]] == [
        "http://web.test/",
        "http://web.test/robots.txt",
        "http://web.test/.git/HEAD",
        "http://web.test/admin",
        "http://web.test/login",
    ]
    assert calls[5][0] == "http_post"
    assert calls[5][1] == "http://web.test/login"
    assert all(caller == "web_agent" for _, _, caller in calls)
    assert len(calls) == 12
    assert result["candidate_flags"] == ["flag{web_adapter}"]
    assert result["summary"] == "Web Adapter probed 5 URL(s) and performed 7 active interaction(s)."
    findings = {finding["summary"]: finding["evidence"] for finding in result["findings"]}
    assert findings["Detected simple HTML form(s)."]["forms"][0]["inputs"] == [
        "username",
        "password",
    ]
    assert findings["Detected candidate URL parameter(s)."]["parameters"][0]["names"] == [
        "id",
        "debug",
    ]
    active = [
        item for item in result["tool_outputs"]
        if item["metadata"].get("interaction") == "active"
    ]
    assert active[0]["metadata"]["payload"] == {
        "username": "admin",
        "password": "admin",
    }
    assert active[1]["metadata"]["payload"] == {"id": "'"}
    assert active[1]["metadata"]["judgment"]["baseline_length"] > 0


def test_web_adapter_stops_requests_when_http_budget_is_exhausted():
    calls = []

    def fake_tool_executor(name: str, request: dict, *, caller: str) -> dict:
        calls.append(request["url"])
        return {
            "tool": "http_get",
            "ok": True,
            "output": "ok",
            "error": None,
            "exit_code": 0,
            "metadata": {"url": request["url"]},
        }

    state = initial_state("web-budget")
    state["remote_targets"] = ["http://web.test/"]
    state["budget"] = {**state["budget"], "max_http_requests": 2}

    result = WebToolAdapter(tool_executor=fake_tool_executor).execute(state)

    assert calls == ["http://web.test/", "http://web.test/robots.txt"]
    assert len(result["tool_outputs"]) == 5
    assert result["tool_outputs"][2]["metadata"]["budget_denied"] is True
    assert result["tool_outputs"][2]["error"] == "budget denied: max_http_requests exhausted"
