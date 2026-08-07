import hashlib

from cyberagent.tools.filesystem import inspect_file


def test_inspect_file_returns_metadata(tmp_path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("hello", encoding="utf-8")

    result = inspect_file(file_path)

    assert result["tool"] == "file_inspect"
    assert result["ok"] is True
    assert result["error"] is None
    assert result["exit_code"] == 0
    assert result["metadata"]["path"] == str(file_path)
    assert result["metadata"]["name"] == "sample.txt"
    assert result["metadata"]["suffix"] == ".txt"
    assert result["metadata"]["size"] == 5
    assert result["metadata"]["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert result["metadata"]["preview_text"] == "hello"
    assert result["metadata"]["preview_hex"] == "68656c6c6f"
    assert result["metadata"]["truncated"] is False


def test_inspect_file_reports_truncated_preview(tmp_path):
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"abcdef")

    result = inspect_file(file_path, max_bytes=3)

    assert result["ok"] is True
    assert result["metadata"]["preview_text"] == "abc"
    assert result["metadata"]["preview_hex"] == "616263"
    assert result["metadata"]["truncated"] is True


def test_inspect_file_handles_missing_file(tmp_path):
    result = inspect_file(tmp_path / "missing.txt")

    assert result["ok"] is False
    assert result["error"] == "file does not exist"


def test_inspect_file_rejects_directory(tmp_path):
    result = inspect_file(tmp_path)

    assert result["ok"] is False
    assert result["error"] == "path is not a file"
