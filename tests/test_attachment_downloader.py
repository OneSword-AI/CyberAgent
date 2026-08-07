from pathlib import Path

from cyberagent.agents.attachment_downloader import download_attachments
from cyberagent.graph import initial_state


def test_download_attachments_copies_local_file(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("flag{attachment}", encoding="utf-8")
    state = initial_state("attach01")
    state["attachments"] = [str(source)]
    state["artifacts_dir"] = str(tmp_path / "artifacts")

    result = download_attachments(state)

    downloaded = result["downloaded_attachments"][0]
    assert downloaded["ok"] is True
    assert Path(downloaded["path"]).exists()
    assert Path(downloaded["path"]).read_text(encoding="utf-8") == "flag{attachment}"
    assert result["tool_outputs"][0]["tool"] == "attachment_download"
    assert result["tool_outputs"][1]["tool"] == "file_inspect"
    assert result["findings"][-1]["agent"] == "download_attachments"


def test_download_attachments_records_missing_file_error(tmp_path):
    state = initial_state("attach01")
    state["attachments"] = [str(tmp_path / "missing.txt")]
    state["artifacts_dir"] = str(tmp_path / "artifacts")

    result = download_attachments(state)

    downloaded = result["downloaded_attachments"][0]
    assert downloaded["ok"] is False
    assert result["tool_outputs"][0]["tool"] == "attachment_download"
    assert result["tool_outputs"][0]["ok"] is False


def test_download_attachments_skips_empty_attachment_list():
    state = initial_state("attach01")

    result = download_attachments(state)

    assert result["downloaded_attachments"] == []
    assert result["trace"][-1]["event"] == "attachment.skip"
