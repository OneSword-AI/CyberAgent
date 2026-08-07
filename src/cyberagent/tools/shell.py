import os
import subprocess
from pathlib import Path

from cyberagent.tools.models import ToolResult


def run_shell(
    command: str,
    *,
    cwd: str | Path | None = None,
    timeout: float = 30,
    env: dict[str, str] | None = None,
    max_chars: int = 4000,
) -> ToolResult:
    """Run an unrestricted shell command and return a normalized result."""
    try:
        completed = subprocess.run(
            command,
            shell=True,
            cwd=str(cwd) if cwd is not None else None,
            env={**os.environ, **(env or {})},
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = _join_output(exc.stdout, exc.stderr)
        return {
            "tool": "shell",
            "ok": False,
            "output": _truncate(output, max_chars),
            "error": f"command timed out after {timeout} seconds",
            "exit_code": None,
            "metadata": {
                "command": command,
                "cwd": str(cwd) if cwd is not None else None,
                "timeout": timeout,
                "truncated": len(output) > max_chars,
            },
        }
    except Exception as exc:
        return {
            "tool": "shell",
            "ok": False,
            "output": "",
            "error": str(exc),
            "exit_code": None,
            "metadata": {
                "command": command,
                "cwd": str(cwd) if cwd is not None else None,
                "timeout": timeout,
                "truncated": False,
            },
        }

    output = _join_output(completed.stdout, completed.stderr)
    return {
        "tool": "shell",
        "ok": completed.returncode == 0,
        "output": _truncate(output, max_chars),
        "error": None if completed.returncode == 0 else f"exit code {completed.returncode}",
        "exit_code": completed.returncode,
        "metadata": {
            "command": command,
            "cwd": str(cwd) if cwd is not None else None,
            "timeout": timeout,
            "truncated": len(output) > max_chars,
        },
    }


def _join_output(stdout: str | bytes | None, stderr: str | bytes | None) -> str:
    parts = [_to_text(stdout), _to_text(stderr)]
    return "\n".join(part for part in parts if part)


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _truncate(value: str, max_chars: int) -> str:
    return value[:max_chars]
