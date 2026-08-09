from cyberagent.tools.defaults import build_default_tool_registry, execute_tool


def test_default_tool_registry_describes_basic_tools():
    registry = build_default_tool_registry()

    names = {tool["name"] for tool in registry.describe_all()}

    assert {"http_get", "http_post", "shell", "file_inspect"} <= names


def test_execute_tool_denies_unsafe_request():
    result = execute_tool(
        "shell",
        {"command": "echo $OPENAI_API_KEY"},
        caller="test",
    )

    assert result["ok"] is False
    assert result["error"] == "L0 denied: action references protected credentials"
