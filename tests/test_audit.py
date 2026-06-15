"""单元测试：审计导出模块。"""

from pathlib import Path
import json
import csv

import pytest

from log_redaction.audit import AuditEntry, AuditExporter, AuditLog


def _build_sample_audit() -> AuditLog:
    audit = AuditLog()
    audit.source_file = "/tmp/in.log"
    audit.output_file = "/tmp/out.log"
    audit.add_entry(
        AuditEntry(
            line_number=1,
            sensitive_type="phone",
            pattern_name="china-mobile-phone",
            original_value="13812345678",
            redacted_value="138****5678",
            start_pos=5,
            end_pos=16,
        )
    )
    audit.add_entry(
        AuditEntry(
            line_number=2,
            sensitive_type="email",
            pattern_name="email-address",
            original_value="user@example.com",
            redacted_value="u***@example.com",
            start_pos=3,
            end_pos=19,
        )
    )
    return audit


class TestAuditLog:
    def test_counts(self):
        audit = _build_sample_audit()
        assert audit.total_count == 2
        assert audit.count_by_type() == {"phone": 1, "email": 1}
        assert audit.count_by_pattern() == {
            "china-mobile-phone": 1,
            "email-address": 1,
        }
        assert audit.count_by_line() == {1: 1, 2: 1}

    def test_entries_sorted(self):
        audit = AuditLog()
        audit.add_entry(
            AuditEntry(2, "phone", "p", "a", "b", 0, 1)
        )
        audit.add_entry(
            AuditEntry(1, "email", "e", "a", "b", 10, 11)
        )
        entries = audit.entries
        assert entries[0].line_number == 1
        assert entries[1].line_number == 2


class TestAuditExporter:
    def test_to_dict(self):
        audit = _build_sample_audit()
        data = AuditExporter.to_dict(audit)
        assert data["source_file"] == "/tmp/in.log"
        assert data["summary"]["total_count"] == 2
        assert len(data["entries"]) == 2

    def test_export_json(self, tmp_path: Path):
        audit = _build_sample_audit()
        output = tmp_path / "report.json"
        AuditExporter.export_json(audit, output)
        assert output.exists()
        data = json.loads(output.read_text(encoding="utf-8"))
        assert data["summary"]["total_count"] == 2

    def test_export_csv(self, tmp_path: Path):
        audit = _build_sample_audit()
        output = tmp_path / "report.csv"
        AuditExporter.export_csv(audit, output)
        assert output.exists()
        with output.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["sensitive_type"] == "phone"

    def test_export_markdown(self, tmp_path: Path):
        audit = _build_sample_audit()
        output = tmp_path / "report.md"
        AuditExporter.export_markdown(audit, output)
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "# 日志脱敏审计报告" in content
        assert "138****5678" in content
        assert "脱敏总条数" in content
