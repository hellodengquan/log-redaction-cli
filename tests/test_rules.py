"""单元测试：敏感信息规则模块。"""

from pathlib import Path
import json
import time

import pytest

from log_redaction.rules import (
    SensitiveType,
    RuleConfigLoader,
    get_default_patterns,
    get_redaction_func,
)


class TestPhonePattern:
    def test_match_basic_phone(self):
        patterns = [
            p for p in get_default_patterns()
            if p.sensitive_type == SensitiveType.PHONE and p.lang == "zh-CN"
        ]
        assert len(patterns) >= 1
        pattern = patterns[0]
        match = pattern.pattern.search("手机号是13812345678已发送")
        assert match is not None
        assert match.group(0) == "13812345678"

    def test_match_phone_with_country_code(self):
        patterns = [
            p for p in get_default_patterns()
            if p.sensitive_type == SensitiveType.PHONE and p.lang == "zh-CN"
        ]
        pattern = patterns[0]
        assert pattern.pattern.search("+8613812345678") is not None
        assert pattern.pattern.search("+86 138 1234 5678") is not None

    def test_match_phone_with_separators(self):
        patterns = [
            p for p in get_default_patterns()
            if p.sensitive_type == SensitiveType.PHONE and p.lang == "zh-CN"
        ]
        pattern = patterns[0]
        match = pattern.pattern.search("138-1234-5678")
        assert match is not None
        assert pattern.redact(match.group(0)) == "138****5678"

    def test_redact_phone(self):
        patterns = [
            p for p in get_default_patterns()
            if p.sensitive_type == SensitiveType.PHONE and p.lang == "zh-CN"
        ]
        pattern = patterns[0]
        assert pattern.redact("13812345678") == "138****5678"
        assert pattern.redact("+8613812345678") == "138****5678"
        assert pattern.redact("138 1234 5678") == "138****5678"

    def test_no_match_invalid_phone(self):
        patterns = [
            p for p in get_default_patterns()
            if p.sensitive_type == SensitiveType.PHONE and p.lang == "zh-CN"
        ]
        pattern = patterns[0]
        assert pattern.pattern.search("12345678901") is None
        assert pattern.pattern.search("12345") is None


class TestEmailPattern:
    def test_match_basic_email(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.EMAIL]
        assert len(patterns) >= 1
        pattern = patterns[0]
        match = pattern.pattern.search("请联系 support@example.com 获取帮助")
        assert match is not None
        assert match.group(0) == "support@example.com"

    def test_match_complex_email(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.EMAIL]
        pattern = patterns[0]
        assert pattern.pattern.search("zhangsan.2024+tag@company.org") is not None
        assert pattern.pattern.search("a_b@mail.test.io") is not None

    def test_redact_email(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.EMAIL]
        pattern = patterns[0]
        assert pattern.redact("zhangsan@example.com") == "z*******@example.com"
        assert pattern.redact("ab@test.cn") == "a*@test.cn"
        assert pattern.redact("a@x.com") == "a@x.com"

    def test_no_match_invalid_email(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.EMAIL]
        pattern = patterns[0]
        assert pattern.pattern.search("not-an-email") is None
        assert pattern.pattern.search("missing@tld") is None


class TestMultilingualPatterns:
    def test_default_has_multilingual(self):
        patterns = get_default_patterns()
        types = {p.sensitive_type for p in patterns}
        assert SensitiveType.PHONE in types
        assert SensitiveType.EMAIL in types
        assert SensitiveType.ID_CARD in types
        assert SensitiveType.BANK_CARD in types
        assert SensitiveType.CHINESE_NAME in types
        assert SensitiveType.US_SSN in types

    def test_id_card_cn_pattern(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.ID_CARD]
        assert len(patterns) >= 1
        pattern = patterns[0]
        match = pattern.pattern.search("身份证号 110101199001011234")
        assert match is not None
        redacted = pattern.redact(match.group(0))
        assert redacted.startswith("110101")
        assert redacted.endswith("1234")
        assert "********" in redacted

    def test_us_ssn_pattern(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.US_SSN]
        assert len(patterns) >= 1
        pattern = patterns[0]
        match = pattern.pattern.search("SSN: 123-45-6789")
        assert match is not None
        assert pattern.redact(match.group(0)) == "***-**-6789"


class TestRedactionFunctionRegistry:
    def test_get_known_func(self):
        fn = get_redaction_func("mask_all")
        assert fn("abc") == "***"

    def test_get_unknown_func_fallback(self):
        fn = get_redaction_func("nonexistent")
        assert fn("abc") == "***"

    def test_mask_first_half(self):
        fn = get_redaction_func("mask_first_half")
        assert fn("abcdef") == "***def"

    def test_mask_last_half(self):
        fn = get_redaction_func("mask_last_half")
        assert fn("abcdef") == "abc***"


class TestRuleConfigLoader:
    def test_load_from_json(self, tmp_path: Path):
        config = {
            "rules": [
                {
                    "name": "custom-rule",
                    "type": "custom",
                    "pattern": "TEST-\\d{4}",
                    "redaction": "mask_all",
                    "description": "自定义规则",
                    "enabled": True,
                }
            ]
        }
        cfg_path = tmp_path / "rules.json"
        cfg_path.write_text(json.dumps(config), encoding="utf-8")
        with RuleConfigLoader(cfg_path) as loader:
            patterns = loader.patterns
            assert len(patterns) == 1
            assert patterns[0].name == "custom-rule"
            assert patterns[0].pattern.pattern == "TEST-\\d{4}"

    def test_reload_if_changed(self, tmp_path: Path):
        config_v1 = {"rules": [{"name": "r1", "pattern": "A", "enabled": True}]}
        cfg_path = tmp_path / "rules.json"
        cfg_path.write_text(json.dumps(config_v1), encoding="utf-8")
        with RuleConfigLoader(cfg_path) as loader:
            assert len(loader.patterns) == 1
            assert loader.patterns[0].name == "r1"
            time.sleep(0.05)
            config_v2 = {
                "rules": [
                    {"name": "r1", "pattern": "A", "enabled": True},
                    {"name": "r2", "pattern": "B", "enabled": True},
                ]
            }
            cfg_path.write_text(json.dumps(config_v2), encoding="utf-8")
            reloaded = loader.reload_if_changed()
            assert reloaded is True
            assert len(loader.patterns) == 2

    def test_invalid_config_skipped(self, tmp_path: Path):
        config = {
            "rules": [
                {"name": "good", "pattern": "\\d+", "enabled": True},
                {"pattern": "missing-name"},
                {"name": "bad-regex", "pattern": "[invalid", "enabled": True},
            ]
        }
        cfg_path = tmp_path / "rules.json"
        cfg_path.write_text(json.dumps(config), encoding="utf-8")
        with RuleConfigLoader(cfg_path) as loader:
            assert len(loader.patterns) == 1
            assert loader.patterns[0].name == "good"
