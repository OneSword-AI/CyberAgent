from cyberagent.tools.shell import run_shell


def test_run_shell_returns_stdout():
    result = run_shell("printf hello")

    assert result["tool"] == "shell"
    assert result["ok"] is True
    assert result["output"] == "hello"
    assert result["error"] is None
    assert result["exit_code"] == 0
    assert result["metadata"]["command"] == "printf hello"


def test_run_shell_captures_nonzero_exit():
    result = run_shell("printf problem >&2; exit 7")

    assert result["ok"] is False
    assert result["output"] == "problem"
    assert result["error"] == "exit code 7"
    assert result["exit_code"] == 7


def test_run_shell_supports_cwd(tmp_path):
    result = run_shell("pwd", cwd=tmp_path)

    assert result["ok"] is True
    assert result["output"].strip() == str(tmp_path)


def test_run_shell_supports_env_override():
    result = run_shell("printf \"$CYBERAGENT_TEST_VALUE\"", env={"CYBERAGENT_TEST_VALUE": "ok"})

    assert result["ok"] is True
    assert result["output"] == "ok"


def test_run_shell_truncates_output():
    result = run_shell("printf abcdef", max_chars=3)

    assert result["output"] == "abc"
    assert result["metadata"]["truncated"] is True


def test_run_shell_handles_timeout():
    result = run_shell("sleep 1", timeout=0.01)

    assert result["ok"] is False
    assert result["exit_code"] is None
    assert "timed out" in result["error"]
