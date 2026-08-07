import pytest

from cyberagent.tools.adapter import FunctionToolAdapter, ToolRegistry


def test_function_tool_adapter_describes_and_executes():
    adapter = FunctionToolAdapter(
        name="echo",
        description="Echo input text.",
        input_schema={"type": "object"},
        handler=lambda request: {
            "tool": "echo",
            "ok": True,
            "output": request["text"],
            "error": None,
            "exit_code": 0,
        },
    )

    assert adapter.describe() == {
        "name": "echo",
        "description": "Echo input text.",
        "input_schema": {"type": "object"},
    }
    assert adapter.execute({"text": "hello"})["output"] == "hello"


def test_tool_registry_registers_and_executes_adapter():
    registry = ToolRegistry()
    registry.register(
        FunctionToolAdapter(
            name="echo",
            description="Echo input text.",
            input_schema={"type": "object"},
            handler=lambda request: {
                "tool": "echo",
                "ok": True,
                "output": request["text"],
                "error": None,
                "exit_code": 0,
            },
        )
    )

    assert registry.execute("echo", {"text": "hello"})["output"] == "hello"
    assert registry.describe_all()[0]["name"] == "echo"


def test_tool_registry_rejects_duplicate_names():
    registry = ToolRegistry()
    adapter = FunctionToolAdapter(
        name="echo",
        description="Echo input text.",
        input_schema={},
        handler=lambda request: {
            "tool": "echo",
            "ok": True,
            "output": "",
            "error": None,
            "exit_code": 0,
        },
    )

    registry.register(adapter)

    with pytest.raises(ValueError):
        registry.register(adapter)


def test_tool_registry_rejects_unknown_tool():
    with pytest.raises(KeyError):
        ToolRegistry().execute("missing", {})
