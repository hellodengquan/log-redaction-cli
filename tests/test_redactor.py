"""单元测试：脱敏处理器模块。"""

from pathlib import Path
import random
import string

import pytest

from log_redaction.redactor import Redactor, DEFAULT_CHUNK_LINES
from log_redaction.rules import SensitiveType, get_default_patterns


class TestRedactor:
    def test_scan_line_no_match(self):
        redactor = Redactor()
        result = redactor.scan_line("这行没有任何敏感信息", line_number=1)
        assert result.has_changes is False
        assert result.redacted == "这行没有任何敏感信息"
        assert len(result.matches) == 0

    def test_scan_line_single_phone(self):
        redactor = Redactor()
        result = redactor.scan_line("手机号 13812345678 已验证", line_number=2)
        assert result.has_changes is True
        assert result.redacted == "手机号 138****5678 已验证"
        assert len(result.matches) == 1
        assert result.matches[0].sensitive_type == "phone"
        assert result.matches[0].original_value == "13812345678"
        assert result.matches[0].redacted_value == "138****5678"

    def test_scan_line_single_email(self):
        redactor = Redactor()
        result = redactor.scan_line("邮箱是 user@example.com 请查收", line_number=3)
        assert result.has_changes is True
        assert "u***@example.com" in result.redacted
        assert len(result.matches) == 1
        assert result.matches[0].sensitive_type == "email"

    def test_scan_line_multiple_matches(self):
        redactor = Redactor()
        result = redactor.scan_line(
            "手机号13812345678和邮箱admin@test.cn在同一行", line_number=4
        )
        assert result.has_changes is True
        assert "138****5678" in result.redacted
        assert "a****@test.cn" in result.redacted
        assert len(result.matches) == 2

    def test_scan_text(self):
        redactor = Redactor()
        text = """登录日志:
用户 13911112222 登录成功
邮箱 aaa@bbb.com 已验证
"""
        redacted, audit = redactor.scan_text(text)
        assert "139****2222" in redacted
        assert "a**@bbb.com" in redacted
        assert audit.total_count == 2
        assert audit.count_by_type() == {"phone": 1, "email": 1}

    def test_process_file(self, tmp_path: Path):
        redactor = Redactor()
        input_file = tmp_path / "test.log"
        input_file.write_text(
            "line1: 13812345678\nline2: test@example.com\n", encoding="utf-8"
        )
        output_file = tmp_path / "test_redacted.log"
        audit = redactor.process_file(input_file, output_file)

        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "138****5678" in content
        assert "t***@example.com" in content
        assert audit.total_count == 2
        assert audit.source_file == str(input_file.resolve())
        assert audit.output_file == str(output_file.resolve())

    def test_set_patterns_hot_reload(self):
        redactor = Redactor()
        defaults = [p for p in get_default_patterns() if p.enabled]
        phone_only = [p for p in defaults if p.sensitive_type == SensitiveType.PHONE]
        redactor.set_patterns(phone_only)
        result = redactor.scan_line("邮箱 user@x.com 和手机 13812345678", 1)
        assert result.has_changes is True
        assert "138****5678" in result.redacted
        assert "user@x.com" in result.redacted


class TestParallelProcessing:
    def _generate_large_log(self, lines: int, seed: int = 42) -> str:
        random.seed(seed)
        out_lines = []
        for i in range(lines):
            parts = [f"2026-06-15 10:00:{i % 60:02d}", f"line-{i}"]
            if i % 3 == 0:
                phone = "1" + "".join(random.choices(string.digits, k=10))
                parts.append(f"phone={phone}")
            if i % 4 == 0:
                name = "".join(random.choices(string.ascii_lowercase, k=6))
                parts.append(f"email={name}@example.com")
            out_lines.append(" ".join(parts))
        return "\n".join(out_lines) + "\n"

    def test_parallel_matches_serial(self, tmp_path: Path):
        content = self._generate_large_log(300)
        input_file = tmp_path / "big.log"
        input_file.write_text(content, encoding="utf-8")

        serial = Redactor(workers=0)
        output_s = tmp_path / "out_serial.log"
        audit_s = serial.process_file(input_file, output_s)

        parallel = Redactor(workers=2, chunk_lines=100)
        output_p = tmp_path / "out_parallel.log"
        audit_p = parallel.process_file(input_file, output_p, workers=2, chunk_lines=100)

        assert output_s.read_text(encoding="utf-8") == output_p.read_text(encoding="utf-8")
        assert audit_s.total_count == audit_p.total_count
        assert audit_s.count_by_type() == audit_p.count_by_type()

    def test_parallel_hash_chain_valid(self, tmp_path: Path):
        content = self._generate_large_log(500)
        input_file = tmp_path / "big.log"
        input_file.write_text(content, encoding="utf-8")
        parallel = Redactor(workers=2, chunk_lines=150)
        audit = parallel.process_file(
            input_file, tmp_path / "out.log", workers=2, chunk_lines=150
        )
        valid, invalid = audit.verify_chain()
        assert valid, f"Hash 链失败: {invalid}"
