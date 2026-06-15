"""合规存储上传与资源限额单元测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from log_redaction.storage import (
    LocalArchiveUploader,
    UploadManifest,
    UploadResult,
    create_uploader,
)
from log_redaction.limiter import (
    ResourceLimitExceeded,
    ResourceLimits,
    ResourceLimiter,
    format_size,
    stream_lines,
    stream_lines_batch,
)


class TestLocalArchiveUploader:
    def test_upload_file(self, tmp_path):
        archive = tmp_path / "archive"
        src = tmp_path / "report.json"
        src.write_text('{"summary": {"total_count": 3}}')
        uploader = LocalArchiveUploader(archive_dir=archive, date_prefix=False)
        result = uploader.upload(src)
        assert result.success is True
        assert result.file_size > 0
        assert len(result.checksum_sha256) == 64
        assert Path(result.destination).exists()

    def test_upload_with_date_prefix(self, tmp_path):
        archive = tmp_path / "archive"
        src = tmp_path / "report.json"
        src.write_text("data")
        uploader = LocalArchiveUploader(archive_dir=archive, date_prefix=True)
        result = uploader.upload(src)
        assert result.success is True
        assert result.destination != str(archive / "report.json")

    def test_upload_nonexistent_file(self, tmp_path):
        uploader = LocalArchiveUploader(archive_dir=tmp_path / "archive")
        result = uploader.upload(tmp_path / "nonexistent.txt")
        assert result.success is False
        assert "不存在" in result.error

    def test_upload_with_custom_key(self, tmp_path):
        archive = tmp_path / "archive"
        src = tmp_path / "report.json"
        src.write_text("data")
        uploader = LocalArchiveUploader(archive_dir=archive, date_prefix=False)
        result = uploader.upload(src, remote_key="custom_name.json")
        assert result.success is True
        assert "custom_name.json" in result.destination

    def test_upload_creates_manifest(self, tmp_path):
        archive = tmp_path / "archive"
        src = tmp_path / "report.json"
        src.write_text("data")
        uploader = LocalArchiveUploader(archive_dir=archive, date_prefix=False)
        uploader.upload(src)
        manifest_path = archive / "upload_manifest.json"
        assert manifest_path.exists()
        manifest = UploadManifest.load(manifest_path)
        assert len(manifest.uploads) == 1

    def test_list_uploads(self, tmp_path):
        archive = tmp_path / "archive"
        src = tmp_path / "report.json"
        src.write_text("data")
        uploader = LocalArchiveUploader(archive_dir=archive, date_prefix=False)
        uploader.upload(src)
        uploads = uploader.list_uploads()
        assert len(uploads) == 1


class TestUploadManifest:
    def test_save_and_load(self, tmp_path):
        path = tmp_path / "manifest.json"
        manifest = UploadManifest(manifest_path=str(path))
        manifest.add(UploadResult(success=True, destination="/tmp/a", checksum_sha256="abc", file_size=100))
        manifest.save(path)
        loaded = UploadManifest.load(path)
        assert len(loaded.uploads) == 1
        assert loaded.uploads[0]["success"] is True

    def test_load_nonexistent(self, tmp_path):
        manifest = UploadManifest.load(tmp_path / "nonexistent.json")
        assert manifest.uploads == []


class TestCreateUploader:
    def test_local_backend(self, tmp_path):
        uploader = create_uploader(backend="local", archive_dir=tmp_path)
        assert isinstance(uploader, LocalArchiveUploader)

    def test_invalid_backend(self):
        with pytest.raises(ValueError, match="不支持的存储后端"):
            create_uploader(backend="ftp")


class TestResourceLimits:
    def test_default_limits(self):
        limits = ResourceLimits()
        assert limits.max_input_file_size == 0
        assert limits.max_output_file_size == 0

    def test_conservative_limits(self):
        limits = ResourceLimits.conservative()
        assert limits.max_input_file_size == 500 * 1024 * 1024
        assert limits.max_memory_mb == 512

    def test_strict_limits(self):
        limits = ResourceLimits.strict()
        assert limits.max_input_file_size == 50 * 1024 * 1024
        assert limits.max_lines == 1_000_000


class TestResourceLimiter:
    def test_check_input_file_ok(self, tmp_path):
        f = tmp_path / "small.txt"
        f.write_text("hello")
        limiter = ResourceLimiter(ResourceLimits(max_input_file_size=1024))
        limiter.check_input_file(f)

    def test_check_input_file_exceeded(self, tmp_path):
        f = tmp_path / "big.txt"
        f.write_text("x" * 100)
        limiter = ResourceLimiter(ResourceLimits(max_input_file_size=50))
        with pytest.raises(ResourceLimitExceeded, match="输入文件大小"):
            limiter.check_input_file(f)

    def test_check_line_ok(self):
        limiter = ResourceLimiter(ResourceLimits(max_line_length=100))
        limiter.check_line("short line")

    def test_check_line_exceeded(self):
        limiter = ResourceLimiter(ResourceLimits(max_line_length=10))
        with pytest.raises(ResourceLimitExceeded, match="单行长度"):
            limiter.check_line("this is a very long line that exceeds the limit")

    def test_check_max_lines(self):
        limiter = ResourceLimiter(ResourceLimits(max_lines=2))
        limiter.check_line("line 1")
        limiter.check_line("line 2")
        with pytest.raises(ResourceLimitExceeded, match="处理行数"):
            limiter.check_line("line 3")

    def test_check_output_size(self):
        limiter = ResourceLimiter(ResourceLimits(max_output_file_size=100))
        limiter.check_output_size(50)
        limiter.check_output_size(49)
        with pytest.raises(ResourceLimitExceeded, match="输出文件大小"):
            limiter.check_output_size(10)

    def test_no_limits(self):
        limiter = ResourceLimiter(ResourceLimits())
        limiter.check_line("x" * 100000)
        limiter.check_output_size(10**12)


class TestStreamLines:
    def test_stream_all_lines(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_text("line1\nline2\nline3\n")
        lines = list(stream_lines(f))
        assert len(lines) == 3
        assert lines[0] == (1, "line1\n")
        assert lines[2] == (3, "line3\n")

    def test_stream_with_limiter(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_text("line1\nline2\nline3\n")
        limiter = ResourceLimiter(ResourceLimits(max_lines=2))
        streamed = []
        with pytest.raises(ResourceLimitExceeded):
            for line_no, line in stream_lines(f, limiter=limiter):
                streamed.append(line)
        assert len(streamed) == 2

    def test_stream_input_size_exceeded(self, tmp_path):
        f = tmp_path / "big.log"
        f.write_text("x" * 200)
        limiter = ResourceLimiter(ResourceLimits(max_input_file_size=100))
        with pytest.raises(ResourceLimitExceeded, match="输入文件大小"):
            list(stream_lines(f, limiter=limiter))


class TestStreamLinesBatch:
    def test_batch_streaming(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_text("\n".join(f"line{i}" for i in range(10)) + "\n")
        batches = list(stream_lines_batch(f, batch_size=3))
        assert len(batches) == 4
        assert len(batches[0][1]) == 3
        assert len(batches[-1][1]) == 1


class TestFormatSize:
    def test_bytes(self):
        assert format_size(100) == "100.0B"

    def test_kb(self):
        assert format_size(2048) == "2.0KB"

    def test_mb(self):
        assert format_size(1048576) == "1.0MB"

    def test_gb(self):
        assert format_size(1073741824) == "1.0GB"
