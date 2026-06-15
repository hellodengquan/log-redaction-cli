"""端到端集成测试。

覆盖：
- CLI 命令 redact / scan / audit / verify / rules 的完整流程
- 自定义规则配置加载 + hot reload
- 多语言敏感信息识别
- 大文件并发处理结果与串行一致
- 审计报告 hash 链完整可校验
- 保持与原 CLI 协议兼容
"""

from __future__ import annotations

import json
import os
import random
import string
import subprocess
import sys
from pathlib import Path

import pytest

from typer.testing import CliRunner

from log_redaction.cli import app


runner = CliRunner()
EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _run(cmd: list, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "log_redaction.cli", *cmd],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )


class TestCLICompatibility:
    def test_help_shows_commands(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for name in ("redact", "scan", "audit", "verify", "rules"):
            assert name in result.stdout

    def test_rules_command(self):
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0
        assert "china-mobile-phone" in result.stdout
        assert "email-address" in result.stdout

    def test_rules_show_all(self):
        result = runner.invoke(app, ["rules", "--all"])
        assert result.exit_code == 0
        assert "china-id-card" in result.stdout
        assert "us_ssn" in result.stdout


class TestCLIRedactAndAudit:
    def test_redact_scan_full_flow(self, tmp_path: Path):
        src = tmp_path / "app.log"
        src.write_text(
            "2026-06-15 user login phone=13812345678\n"
            "2026-06-15 user email: alice@example.com\n",
            encoding="utf-8",
        )
        out = tmp_path / "app_redacted.log"
        audit_json = tmp_path / "audit.json"
        result = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out),
                "-a",
                str(audit_json),
                "-f",
                "json",
            ],
        )
        assert result.exit_code == 0
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "138****5678" in content
        assert "a****@example.com" in content
        assert audit_json.exists()

        data = json.loads(audit_json.read_text(encoding="utf-8"))
        assert data["summary"]["total_count"] == 2
        assert data["hash_chain"]["valid"] is True

        verify_result = runner.invoke(app, ["verify", str(audit_json)])
        assert verify_result.exit_code == 0
        assert "完整有效" in verify_result.stdout

    def test_scan_only(self, tmp_path: Path):
        src = tmp_path / "app.log"
        src.write_text("phone 13812345678 email a@b.com\n", encoding="utf-8")
        result = runner.invoke(app, ["scan", str(src), "--show-lines"])
        assert result.exit_code == 0
        assert "138****5678" in result.stdout

    def test_audit_markdown(self, tmp_path: Path):
        src = tmp_path / "app.log"
        src.write_text("phone 13911112222\n", encoding="utf-8")
        md = tmp_path / "audit.md"
        result = runner.invoke(
            app, ["audit", str(src), str(md), "-f", "markdown"]
        )
        assert result.exit_code == 0
        assert md.exists()
        content = md.read_text(encoding="utf-8")
        assert "# 日志脱敏审计报告" in content
        assert "Hash 链校验" in content


class TestCLICustomRuleConfig:
    def test_custom_rules_config(self, tmp_path: Path):
        cfg = tmp_path / "custom_rules.json"
        cfg.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "name": "order-no",
                            "type": "custom",
                            "pattern": "ORD-[A-Z]{2}\\d{6}",
                            "redaction": "mask_last_half",
                            "description": "订单号",
                            "enabled": True,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        src = tmp_path / "orders.log"
        src.write_text("订单 ORD-AB123456 已完成\n", encoding="utf-8")
        out = tmp_path / "orders_redacted.log"
        result = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out),
                "--config",
                str(cfg),
                "--no-phone",
                "--no-email",
            ],
        )
        assert result.exit_code == 0
        content = out.read_text(encoding="utf-8")
        assert "ORD-AB" in content
        assert "123456" not in content

    def test_rules_with_config(self, tmp_path: Path):
        cfg = tmp_path / "rules.json"
        cfg.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "name": "my-rule",
                            "pattern": "FOO",
                            "enabled": True,
                            "description": "测试规则",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["rules", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "my-rule" in result.stdout


class TestCLIMultilingual:
    def test_id_card_extra_type(self, tmp_path: Path):
        src = tmp_path / "multi.log"
        src.write_text(
            "用户张三 身份证 110101199003076543 手机 13812345678\n",
            encoding="utf-8",
        )
        out = tmp_path / "multi_redacted.log"
        result = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out),
                "--id-card",
            ],
        )
        assert result.exit_code == 0
        content = out.read_text(encoding="utf-8")
        assert "138****5678" in content
        assert "110101" in content
        assert "6543" in content
        assert "19900307" not in content

    def test_lang_filter_zh_cn(self, tmp_path: Path):
        result = runner.invoke(app, ["rules", "--lang", "zh-CN", "--all"])
        assert result.exit_code == 0
        assert "china-mobile-phone" in result.stdout
        assert "us-mobile-phone" not in result.stdout


class TestCLIParallelLargeFile:
    def _make_big(self, tmp_path: Path, lines: int = 400) -> Path:
        random.seed(0)
        buf = []
        for i in range(lines):
            row = f"[{i}] "
            if i % 3 == 0:
                n = "1" + "".join(random.choices(string.digits, k=10))
                row += f"phone={n} "
            if i % 5 == 0:
                name = "".join(random.choices(string.ascii_lowercase, k=6))
                row += f"email={name}@example.com"
            buf.append(row)
        p = tmp_path / "big.log"
        p.write_text("\n".join(buf) + "\n", encoding="utf-8")
        return p

    def test_parallel_vs_serial_consistency(self, tmp_path: Path):
        src = self._make_big(tmp_path, lines=300)

        out_s = tmp_path / "s.log"
        audit_s = tmp_path / "s.json"
        r1 = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out_s),
                "-a",
                str(audit_s),
            ],
        )
        assert r1.exit_code == 0

        out_p = tmp_path / "p.log"
        audit_p = tmp_path / "p.json"
        r2 = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out_p),
                "-a",
                str(audit_p),
                "-w",
                "2",
                "--chunk-lines",
                "100",
            ],
        )
        assert r2.exit_code == 0

        assert out_s.read_text(encoding="utf-8") == out_p.read_text(encoding="utf-8")

        ds = json.loads(audit_s.read_text(encoding="utf-8"))
        dp = json.loads(audit_p.read_text(encoding="utf-8"))
        assert ds["summary"]["total_count"] == dp["summary"]["total_count"]
        assert dp["hash_chain"]["valid"] is True

        r3 = runner.invoke(app, ["verify", str(audit_p)])
        assert r3.exit_code == 0


class TestCLIEncryption:
    def test_encrypt_output_file(self, tmp_path: Path):
        src = tmp_path / "app.log"
        src.write_text(
            "2026-06-15 user phone=13812345678 email=alice@example.com\n",
            encoding="utf-8",
        )
        out = tmp_path / "app_redacted.enc"
        audit = tmp_path / "audit.json"
        result = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out),
                "-a",
                str(audit),
                "-E",
                "mypassword",
                "--encrypt-output",
            ],
        )
        assert result.exit_code == 0
        assert out.exists()
        from log_redaction.crypto import is_encrypted_file
        assert is_encrypted_file(out) is True

        decrypted = tmp_path / "decrypted.log"
        decrypt_result = runner.invoke(
            app,
            [
                "decrypt",
                str(out),
                str(decrypted),
                "-E",
                "mypassword",
            ],
        )
        assert decrypt_result.exit_code == 0
        content = decrypted.read_text(encoding="utf-8")
        assert "138****5678" in content
        assert "a****@example.com" in content

    def test_encrypt_audit_report(self, tmp_path: Path):
        src = tmp_path / "app.log"
        src.write_text("user phone 13812345678\n", encoding="utf-8")
        out = tmp_path / "redacted.log"
        audit_enc = tmp_path / "audit_enc.json"
        result = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out),
                "-a",
                str(audit_enc),
                "-E",
                "mypassword",
                "--encrypt-audit",
            ],
        )
        assert result.exit_code == 0
        assert audit_enc.exists()
        from log_redaction.crypto import is_encrypted_file
        assert is_encrypted_file(audit_enc) is True

        verify_result = runner.invoke(
            app,
            ["verify", str(audit_enc), "-E", "mypassword"],
        )
        assert verify_result.exit_code == 0
        assert "完整有效" in verify_result.stdout

        verify_wrong_pw = runner.invoke(
            app,
            ["verify", str(audit_enc), "-E", "wrongpassword"],
        )
        assert verify_wrong_pw.exit_code != 0

    def test_decrypt_wrong_password(self, tmp_path: Path):
        from log_redaction.crypto import EncryptionConfig, FileEncryptor
        src = tmp_path / "src.log"
        src.write_text("hello")
        enc = tmp_path / "src.enc"
        enc_config = EncryptionConfig(password="rightpassword")
        encryptor = FileEncryptor(enc_config)
        encryptor.encrypt_file(src, enc)

        out = tmp_path / "out.log"
        result = runner.invoke(
            app,
            ["decrypt", str(enc), str(out), "-E", "wrongpassword"],
        )
        assert result.exit_code == 1
        assert "解密失败" in result.stdout

    def test_audit_command_with_encrypt(self, tmp_path: Path):
        src = tmp_path / "app.log"
        src.write_text("phone 13812345678\n", encoding="utf-8")
        audit_enc = tmp_path / "audit_enc.json"
        result = runner.invoke(
            app,
            [
                "audit",
                str(src),
                str(audit_enc),
                "--encrypt",
                "-E",
                "auditpass",
            ],
        )
        assert result.exit_code == 0
        assert audit_enc.exists()
        from log_redaction.crypto import is_encrypted_file
        assert is_encrypted_file(audit_enc) is True

        verify_result = runner.invoke(
            app,
            ["verify", str(audit_enc), "-E", "auditpass"],
        )
        assert verify_result.exit_code == 0

    def test_decrypt_non_encrypted_file(self, tmp_path: Path):
        src = tmp_path / "plain.txt"
        src.write_text("not encrypted")
        out = tmp_path / "out.txt"
        result = runner.invoke(
            app,
            ["decrypt", str(src), str(out), "-E", "anypassword"],
        )
        assert result.exit_code == 0
        assert "不是 LRED 加密格式" in result.stdout
        assert out.read_text() == "not encrypted"

    def test_help_shows_encrypt_options(self):
        result = runner.invoke(app, ["redact", "--help"])
        assert result.exit_code == 0
        assert "--encrypt-password" in result.stdout
        assert "--encrypt-output" in result.stdout
        assert "--encrypt-audit" in result.stdout
        assert "--log-format" in result.stdout


class TestCLIMultiFormatReader:
    def test_json_lines_format(self, tmp_path: Path):
        src = tmp_path / "app.jsonl"
        lines = [
            json.dumps(
                {
                    "timestamp": "2026-06-15T10:00:00",
                    "level": "INFO",
                    "message": "User login phone 13812345678 email alice@example.com",
                },
                ensure_ascii=False,
            )
            + "\n",
            json.dumps(
                {
                    "timestamp": "2026-06-15T10:00:01",
                    "level": "ERROR",
                    "message": "User login phone 13999998888",
                },
                ensure_ascii=False,
            )
            + "\n",
        ]
        src.write_text("".join(lines), encoding="utf-8")
        out = tmp_path / "redacted.jsonl"
        result = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out),
                "-F",
                "json",
                "--json-field",
                "message",
            ],
        )
        assert result.exit_code == 0
        assert out.exists()
        out_lines = out.read_text(encoding="utf-8").strip().split("\n")
        assert len(out_lines) == 2
        obj1 = json.loads(out_lines[0])
        assert obj1["timestamp"] == "2026-06-15T10:00:00"
        assert obj1["level"] == "INFO"
        assert "138****5678" in obj1["message"]
        assert "a****@example.com" in obj1["message"]
        obj2 = json.loads(out_lines[1])
        assert obj2["level"] == "ERROR"
        assert "139****8888" in obj2["message"]

    def test_json_format_custom_field(self, tmp_path: Path):
        src = tmp_path / "data.jsonl"
        line = json.dumps(
            {"time": "now", "logmsg": "contact 13812345678"},
            ensure_ascii=False,
        )
        src.write_text(line + "\n", encoding="utf-8")
        out = tmp_path / "out.jsonl"
        result = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out),
                "-F",
                "json",
                "--json-field",
                "logmsg",
            ],
        )
        assert result.exit_code == 0
        obj = json.loads(out.read_text().strip())
        assert obj["time"] == "now"
        assert "138****5678" in obj["logmsg"]

    def test_syslog_rfc5424_format(self, tmp_path: Path):
        src = tmp_path / "syslog.log"
        lines = [
            '<134>1 2026-06-15T10:00:00.000Z myhost myapp 1234 - - User login phone 13812345678\n',
            '<134>1 2026-06-15T10:00:01.000Z myhost myapp 1235 - - Send email to bob@test.com\n',
        ]
        src.write_text("".join(lines), encoding="utf-8")
        out = tmp_path / "redacted_syslog.log"
        result = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out),
                "-F",
                "syslog",
            ],
        )
        assert result.exit_code == 0
        out_lines = out.read_text(encoding="utf-8").strip().split("\n")
        assert len(out_lines) == 2
        assert "138****5678" in out_lines[0]
        assert "<134>1 2026-06-15T10:00:00.000Z myhost myapp 1234" in out_lines[0]
        assert "b**@test.com" in out_lines[1]
        assert "<134>1 2026-06-15T10:00:01.000Z myhost myapp 1235" in out_lines[1]

    def test_syslog_rfc3164_format(self, tmp_path: Path):
        src = tmp_path / "bsd_syslog.log"
        line = '<134>Jun 15 10:00:00 myhost myapp[1234]: phone 13812345678'
        src.write_text(line + "\n", encoding="utf-8")
        out = tmp_path / "out.log"
        result = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out),
                "-F",
                "syslog",
            ],
        )
        assert result.exit_code == 0
        content = out.read_text(encoding="utf-8")
        assert "<134>Jun 15 10:00:00 myhost myapp[1234]" in content
        assert "138****5678" in content

    def test_scan_command_with_format(self, tmp_path: Path):
        src = tmp_path / "app.jsonl"
        line = json.dumps({"msg": "contact 13812345678"})
        src.write_text(line + "\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "scan",
                str(src),
                "-F",
                "json",
                "--json-field",
                "msg",
            ],
        )
        assert result.exit_code == 0
        assert "共检测并脱敏 1 条" in result.stdout

    def test_audit_command_with_format(self, tmp_path: Path):
        src = tmp_path / "app.jsonl"
        line = json.dumps({"message": "phone 13812345678"})
        src.write_text(line + "\n", encoding="utf-8")
        audit_out = tmp_path / "audit.json"
        result = runner.invoke(
            app,
            [
                "audit",
                str(src),
                str(audit_out),
                "-F",
                "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(audit_out.read_text())
        assert data["summary"]["total_count"] == 1

    def test_help_shows_log_format(self):
        result = runner.invoke(app, ["redact", "--help"])
        assert result.exit_code == 0
        assert "--log-format" in result.stdout
        assert "--json-field" in result.stdout

    def test_invalid_log_format(self, tmp_path: Path):
        src = tmp_path / "test.log"
        src.write_text("phone 13812345678\n")
        out = tmp_path / "out.log"
        result = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out),
                "-F",
                "invalid_format",
            ],
        )
        assert result.exit_code == 1
        assert "不支持的日志格式" in result.stdout


class TestCLIEncryptedHashChainVerify:
    def test_full_encrypted_audit_verify_flow(self, tmp_path: Path):
        src = tmp_path / "app.log"
        src.write_text(
            "line1 phone 13812345678\n"
            "line2 phone 13999998888\n"
            "line3 email alice@example.com\n",
            encoding="utf-8",
        )
        out = tmp_path / "out.enc"
        audit_enc = tmp_path / "audit.enc.json"

        redact_result = runner.invoke(
            app,
            [
                "redact",
                str(src),
                "-o",
                str(out),
                "-a",
                str(audit_enc),
                "-E",
                "strongpassword123",
                "--encrypt-output",
                "--encrypt-audit",
            ],
        )
        assert redact_result.exit_code == 0
        from log_redaction.crypto import is_encrypted_file
        assert is_encrypted_file(out) is True
        assert is_encrypted_file(audit_enc) is True

        verify_result = runner.invoke(
            app,
            ["verify", str(audit_enc), "-E", "strongpassword123"],
        )
        assert verify_result.exit_code == 0
        assert "完整有效" in verify_result.stdout

        decrypted_out = tmp_path / "decrypted.log"
        decrypt_result = runner.invoke(
            app,
            ["decrypt", str(out), str(decrypted_out), "-E", "strongpassword123"],
        )
        assert decrypt_result.exit_code == 0
        content = decrypted_out.read_text(encoding="utf-8")
        assert "138****5678" in content
        assert "139****8888" in content
        assert "a****@example.com" in content

        decrypted_audit = tmp_path / "decrypted_audit.json"
        decrypt_audit_result = runner.invoke(
            app,
            [
                "decrypt",
                str(audit_enc),
                str(decrypted_audit),
                "-E",
                "strongpassword123",
            ],
        )
        assert decrypt_audit_result.exit_code == 0
        audit_data = json.loads(decrypted_audit.read_text(encoding="utf-8"))
        assert audit_data["summary"]["total_count"] == 3
        assert audit_data["hash_chain"]["valid"] is True
        assert len(audit_data["entries"]) == 3
