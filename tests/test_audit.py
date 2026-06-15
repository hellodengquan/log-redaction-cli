"""单元测试：审计导出模块（含 hash 链）。"""

from pathlib import Path
import json
import csv

import pytest

from log_redaction.audit import (
    AuditEntry,
    AuditExporter,
    AuditLog,
    GENESIS_PREV_HASH,
)


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


class TestAuditLogHashChain:
    def test_entries_have_hash_fields(self):
        audit = _build_sample_audit()
        for entry in audit.entries:
            assert entry.entry_hash, f"entry 缺少 entry_hash"
            assert entry.prev_hash, f"entry 缺少 prev_hash"
            assert entry.timestamp, f"entry 缺少 timestamp"

    def test_first_entry_prev_hash_is_genesis(self):
        audit = _build_sample_audit()
        assert audit.entries[0].prev_hash == GENESIS_PREV_HASH

    def test_hash_chain_links(self):
        audit = _build_sample_audit()
        entries = audit.entries
        assert len(entries) >= 2
        assert entries[1].prev_hash == entries[0].entry_hash

    def test_verify_chain_valid(self):
        audit = _build_sample_audit()
        valid, invalid = audit.verify_chain()
        assert valid is True
        assert invalid == []

    def test_verify_chain_detects_tamper(self):
        audit = _build_sample_audit()
        entries = audit.entries
        entries[0].original_value = "篡改后的值"
        valid, invalid = audit.verify_chain()
        assert valid is False
        assert len(invalid) >= 1

    def test_merkle_root(self):
        audit = _build_sample_audit()
        assert audit.merkle_root == audit.entries[-1].entry_hash

    def test_disabled_hash_chain(self):
        audit = AuditLog(enable_hash_chain=False)
        audit.add_entry(
            AuditEntry(1, "phone", "p", "a", "b", 0, 1)
        )
        valid, invalid = audit.verify_chain()
        assert valid is True
        assert audit.entries[0].entry_hash == ""

    def test_finalize_rebuilds_chain(self):
        audit = AuditLog(enable_hash_chain=False)
        audit.add_entry(AuditEntry(1, "phone", "p", "a", "b", 0, 1))
        audit.add_entry(AuditEntry(2, "email", "e", "c", "d", 0, 1))
        audit._enable_hash_chain = True
        audit.finalize()
        valid, invalid = audit.verify_chain()
        assert valid is True


class TestAuditLogCounts:
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
        audit.add_entry(AuditEntry(2, "phone", "p", "a", "b", 0, 1))
        audit.add_entry(AuditEntry(1, "email", "e", "a", "b", 10, 11))
        entries = audit.entries
        assert entries[0].line_number == 1
        assert entries[1].line_number == 2


class TestAuditExporter:
    def test_to_dict_includes_hash_chain(self):
        audit = _build_sample_audit()
        data = AuditExporter.to_dict(audit)
        assert "hash_chain" in data
        assert data["hash_chain"]["enabled"] is True
        assert data["hash_chain"]["valid"] is True
        assert "merkle_root" in data["hash_chain"]
        assert data["source_file"] == "/tmp/in.log"
        assert data["summary"]["total_count"] == 2
        assert len(data["entries"]) == 2
        for e in data["entries"]:
            assert "entry_hash" in e
            assert "prev_hash" in e
            assert "timestamp" in e

    def test_export_json(self, tmp_path: Path):
        audit = _build_sample_audit()
        output = tmp_path / "report.json"
        AuditExporter.export_json(audit, output)
        assert output.exists()
        data = json.loads(output.read_text(encoding="utf-8"))
        assert data["summary"]["total_count"] == 2
        assert data["hash_chain"]["valid"] is True

    def test_export_csv_has_hash_fields(self, tmp_path: Path):
        audit = _build_sample_audit()
        output = tmp_path / "report.csv"
        AuditExporter.export_csv(audit, output)
        assert output.exists()
        with output.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["sensitive_type"] == "phone"
        assert "entry_hash" in rows[0]
        assert "prev_hash" in rows[0]

    def test_export_markdown(self, tmp_path: Path):
        audit = _build_sample_audit()
        output = tmp_path / "report.md"
        AuditExporter.export_markdown(audit, output)
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "# 日志脱敏审计报告" in content
        assert "138****5678" in content
        assert "脱敏总条数" in content
        assert "Hash 链校验" in content
        assert "Merkle Root" in content

    def test_verify_json_chain_valid(self, tmp_path: Path):
        audit = _build_sample_audit()
        output = tmp_path / "report.json"
        AuditExporter.export_json(audit, output)
        valid, msg = AuditExporter.verify_json_chain(output)
        assert valid is True

    def test_verify_json_chain_tampered(self, tmp_path: Path):
        audit = _build_sample_audit()
        output = tmp_path / "report.json"
        AuditExporter.export_json(audit, output)
        data = json.loads(output.read_text(encoding="utf-8"))
        data["entries"][0]["original_value"] = "被篡改"
        output.write_text(json.dumps(data), encoding="utf-8")
        valid, msg = AuditExporter.verify_json_chain(output)
        assert valid is False

    def test_verify_json_chain_file_not_found(self, tmp_path: Path):
        valid, msg = AuditExporter.verify_json_chain(tmp_path / "missing.json")
        assert valid is False
        assert "不存在" in msg
