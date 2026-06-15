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
