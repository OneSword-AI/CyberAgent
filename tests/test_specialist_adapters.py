from cyberagent.agents.specialist_signals import publish_specialist_results
from cyberagent.agents.specialists import crypto_agent, forensics_agent, misc_agent, web_agent
from cyberagent.agents.tool_adapters import (
    AttachmentAnalysisAdapter,
    CryptoAdapter,
    ForensicsAdapter,
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


def test_default_specialist_adapters_expose_web_crypto_misc_and_forensics():
    registry = build_default_specialist_adapters()

    descriptions = registry.describe_all()
    assert {item["name"] for item in descriptions} == {
        "web",
        "crypto",
        "misc",
        "forensics",
    }
    misc_description = next(item for item in descriptions if item["name"] == "misc")
    crypto_description = next(item for item in descriptions if item["name"] == "crypto")
    forensics_description = next(item for item in descriptions if item["name"] == "forensics")
    web_description = next(item for item in descriptions if item["name"] == "web")
    assert {"path_probe", "flag_extract", "form_detect", "parameter_detect"} <= set(
        web_description["capabilities"]
    )
    assert {"file", "strings", "unzip_list"} <= set(misc_description["capabilities"])
    assert {"encoding_detect", "rsa_weakness_detect", "aes_mode_detect"} <= set(
        crypto_description["capabilities"]
    )
    assert {"file", "strings", "unzip_list", "flag_extract"} <= set(
        forensics_description["capabilities"]
    )
    assert {"metadata_extract", "binwalk_scan", "pcap_tshark_summary"} <= set(
        forensics_description["capabilities"]
    )


def test_specialists_can_use_replacement_adapters():
    registry = SpecialistToolAdapterRegistry(
        [
            FakeSpecialistAdapter("web", "custom web adapter"),
            FakeSpecialistAdapter("crypto", "custom crypto adapter"),
            FakeSpecialistAdapter("misc", "custom misc adapter"),
            FakeSpecialistAdapter("forensics", "custom forensics adapter"),
        ]
    )

    web_state = initial_state("web-adapter")
    web_state["active_agents"] = ["web_agent"]
    crypto_state = initial_state("crypto-adapter")
    crypto_state["active_agents"] = ["crypto_agent"]
    misc_state = initial_state("misc-adapter")
    misc_state["active_agents"] = ["misc_agent"]
    forensics_state = initial_state("forensics-adapter")
    forensics_state["active_agents"] = ["forensics_agent"]

    web_result = web_agent(web_state, adapters=registry)
    crypto_result = crypto_agent(crypto_state, adapters=registry)
    misc_result = misc_agent(misc_state, adapters=registry)
    forensics_result = forensics_agent(forensics_state, adapters=registry)

    assert web_result["summary"] == "custom web adapter"
    assert crypto_result["summary"] == "custom crypto adapter"
    assert misc_result["summary"] == "custom misc adapter"
    assert forensics_result["summary"] == "custom forensics adapter"
    assert web_result["candidate_flags"] == ["flag{web}"]
    assert crypto_result["candidate_flags"] == ["flag{crypto}"]
    assert misc_result["candidate_flags"] == ["flag{misc}"]
    assert forensics_result["candidate_flags"] == ["flag{forensics}"]


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
    assert result["candidate_flags"] == ["flag{inside_zip}"]
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


def test_forensics_adapter_reuses_basic_attachment_analysis_tools():
    calls = []

    def fake_tool_executor(name: str, request: dict, *, caller: str) -> dict:
        calls.append((name, request["command"], caller))
        output = "PNG image data" if request["command"].startswith("file ") else "note flag{forensics_artifact}"
        return {
            "tool": "shell",
            "ok": True,
            "output": output,
            "error": None,
            "exit_code": 0,
            "metadata": {"command": request["command"]},
        }

    state = initial_state("forensics-adapter")
    state["downloaded_attachments"] = [
        {
            "source": "image.png",
            "path": "/tmp/image.png",
            "ok": True,
            "error": None,
        }
    ]

    result = ForensicsAdapter(tool_executor=fake_tool_executor).execute(state)

    assert [command for _, command, _ in calls] == [
        "file -b /tmp/image.png",
        "strings -n 4 /tmp/image.png | head -200",
        "binwalk /tmp/image.png",
        "exiftool /tmp/image.png",
    ]
    assert all(caller == "forensics_agent" for _, _, caller in calls)
    assert result["summary"] == "Forensics Adapter analyzed 1 downloaded attachment(s)."
    assert result["candidate_flags"] == ["flag{forensics_artifact}"]
    assert result["findings"][0]["agent"] == "forensics_agent"
    assert [output["metadata"]["analysis"] for output in result["tool_outputs"]] == [
        "file",
        "strings",
        "binwalk",
        "metadata",
    ]


def test_forensics_adapter_runs_pcap_tshark_analysis():
    calls = []

    def fake_tool_executor(name: str, request: dict, *, caller: str) -> dict:
        calls.append((name, request["command"], caller))
        if request["command"].startswith("file "):
            output = "pcap capture file"
        elif "pcap_protocols" in request["command"]:
            output = ""
        elif request["command"].startswith("tshark "):
            output = "HTTP GET /flag flag{pcap_trace}"
        else:
            output = "DECIMAL HEXADECIMAL DESCRIPTION"
        return {
            "tool": "shell",
            "ok": True,
            "output": output,
            "error": None,
            "exit_code": 0,
            "metadata": {"command": request["command"]},
        }

    state = initial_state("forensics-pcap")
    state["downloaded_attachments"] = [
        {
            "source": "traffic.pcap",
            "path": "/tmp/traffic.pcap",
            "ok": True,
            "error": None,
        }
    ]

    result = ForensicsAdapter(tool_executor=fake_tool_executor).execute(state)

    commands = [command for _, command, _ in calls]
    assert commands == [
        "file -b /tmp/traffic.pcap",
        "strings -n 4 /tmp/traffic.pcap | head -200",
        "binwalk /tmp/traffic.pcap",
        "tshark -r /tmp/traffic.pcap -q -z io,phs",
        "tshark -r /tmp/traffic.pcap -T fields -e frame.number -e _ws.col.Protocol -e _ws.col.Info -c 80",
    ]
    assert result["candidate_flags"] == ["flag{pcap_trace}"]
    assert result["findings"][0]["evidence"]["analyses"] == [
        "file",
        "strings",
        "binwalk",
        "pcap_summary",
        "pcap_protocols",
    ]


def test_crypto_adapter_detects_encoded_flags():
    state = initial_state("crypto-encoding")
    state["description"] = "The note says 666c61677b6865785f6465636f64657d"

    result = CryptoAdapter().execute(state)

    assert result["candidate_flags"] == ["flag{hex_decode}"]
    assert result["tool_outputs"][0]["tool"] == "crypto_analysis"
    assert result["tool_outputs"][0]["metadata"]["encoding_count"] == 1
    assert result["findings"][0]["summary"] == "Detected encoded value(s)."


def test_crypto_adapter_detects_rsa_weakness_clues():
    state = initial_state("crypto-rsa")
    state["description"] = "RSA params: n=3233, e=3, c=42, p=61, q=53"

    result = CryptoAdapter().execute(state)

    rsa = result["findings"][0]["evidence"]["rsa"]
    kinds = {item["kind"] for item in rsa}
    assert {"factor_provided", "small_public_exponent", "standard_rsa_tuple"} <= kinds
    assert result["next_actions"][0]["kind"] == "crypto_rsa_attack"


def test_crypto_adapter_detects_aes_mode_and_repeated_blocks():
    repeated_hex = "00112233445566778899aabbccddeeff" * 2
    state = initial_state("crypto-aes")
    state["description"] = f"AES ECB ciphertext {repeated_hex}"

    result = CryptoAdapter().execute(state)

    findings = {finding["summary"]: finding["evidence"] for finding in result["findings"]}
    aes = findings["Detected AES mode clue(s)."]["aes"]
    kinds = {item["kind"] for item in aes}
    assert {"mode_keyword", "repeated_cipher_blocks"} <= kinds
    assert "crypto_aes_analysis" in {action["kind"] for action in result["next_actions"]}


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
