import hashlib
from pathlib import Path

from cyberagent.tools.models import ToolResult


def inspect_file(path: str | Path, *, max_bytes: int = 512) -> ToolResult:
    """Inspect a local file and return metadata useful for CTF triage."""
    file_path = Path(path)

    if not file_path.exists():
        return _error_result(file_path, "file does not exist")
    if not file_path.is_file():
        return _error_result(file_path, "path is not a file")

    try:
        size = file_path.stat().st_size
        digest = _sha256(file_path)
        preview = file_path.read_bytes()[:max_bytes]
    except Exception as exc:
        return _error_result(file_path, str(exc))

    return {
        "tool": "file_inspect",
        "ok": True,
        "output": f"{file_path} size={size} sha256={digest}",
        "error": None,
        "exit_code": 0,
        "metadata": {
            "path": str(file_path),
            "name": file_path.name,
            "suffix": file_path.suffix,
            "size": size,
            "sha256": digest,
            "preview_hex": preview.hex(),
            "preview_text": preview.decode("utf-8", errors="replace"),
            "truncated": size > max_bytes,
        },
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _error_result(path: Path, error: str) -> ToolResult:
    return {
        "tool": "file_inspect",
        "ok": False,
        "output": "",
        "error": error,
        "exit_code": None,
        "metadata": {"path": str(path)},
    }
