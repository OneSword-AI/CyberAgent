import shutil
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import urlopen

from cyberagent.evidence import add_finding
from cyberagent.models import ChallengeState
from cyberagent.tools import ToolResult, inspect_file, record_tool_output
from cyberagent.trace import add_trace_event


def download_attachments(state: ChallengeState) -> ChallengeState:
    """Download/copy attachments into the challenge artifacts directory and inspect them."""
    attachments = state.get("attachments", [])
    if not attachments:
        return add_trace_event(
            state,
            node="download_attachments",
            event="attachment.skip",
            details={"reason": "no attachments"},
        )

    downloaded: list[dict] = []
    next_state = state
    target_dir = _attachment_dir(state)
    target_dir.mkdir(parents=True, exist_ok=True)

    for attachment in attachments:
        result = _download_one(str(attachment), target_dir)
        downloaded.append(result)
        next_state = record_tool_output(
            next_state,
            _download_tool_result(result),
            caller="download_attachments",
        )
        if result["ok"]:
            next_state = record_tool_output(
                next_state,
                inspect_file(result["path"]),
                caller="download_attachments",
            )

    next_state = {
        **next_state,
        "downloaded_attachments": [
            *next_state.get("downloaded_attachments", []),
            *downloaded,
        ],
    }
    next_state = add_trace_event(
        next_state,
        node="download_attachments",
        event="attachment.download",
        details={
            "count": len(downloaded),
            "ok": sum(1 for item in downloaded if item["ok"]),
        },
    )
    return add_finding(
        next_state,
        agent="download_attachments",
        summary=f"Processed {len(downloaded)} attachment(s).",
        evidence={"downloaded_attachments": downloaded},
    )


def _attachment_dir(state: ChallengeState) -> Path:
    return Path(state.get("artifacts_dir", "artifacts")) / state.get("challenge_id", "unknown") / "attachments"


def _download_one(source: str, target_dir: Path) -> dict:
    filename = _filename_for(source)
    target = target_dir / filename
    try:
        parsed = urlparse(source)
        if parsed.scheme in {"http", "https"}:
            with urlopen(source, timeout=30) as response:
                target.write_bytes(response.read())
        elif parsed.scheme == "file":
            shutil.copyfile(Path(unquote(parsed.path)), target)
        elif parsed.scheme:
            raise ValueError(f"unsupported attachment scheme: {parsed.scheme}")
        else:
            shutil.copyfile(Path(source), target)
    except Exception as exc:
        return {
            "source": source,
            "path": str(target),
            "ok": False,
            "error": str(exc),
        }

    return {
        "source": source,
        "path": str(target),
        "ok": True,
        "error": None,
    }


def _filename_for(source: str) -> str:
    parsed = urlparse(source)
    candidate = Path(unquote(parsed.path)).name if parsed.scheme else Path(source).name
    return candidate or "attachment.bin"


def _download_tool_result(result: dict) -> ToolResult:
    return {
        "tool": "attachment_download",
        "ok": result["ok"],
        "output": result["path"] if result["ok"] else "",
        "error": result["error"],
        "exit_code": 0 if result["ok"] else 1,
        "metadata": {
            "source": result["source"],
            "path": result["path"],
        },
    }
