"""单元测试：敏感信息规则模块。"""

import pytest

from log_redaction.rules import (
    SensitiveType,
    get_default_patterns,
)


class TestPhonePattern:
    """手机号检测与脱敏测试。"""

    def test_match_basic_phone(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.PHONE]
        assert len(patterns) == 1
        pattern = patterns[0]

        match = pattern.pattern.search("手机号是13812345678已发送")
        assert match is not None
        assert match.group(0) == "13812345678"

    def test_match_phone_with_country_code(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.PHONE]
        pattern = patterns[0]

        match = pattern.pattern.search("+8613812345678")
        assert match is not None

        match = pattern.pattern.search("+86 138 1234 5678")
        assert match is not None

    def test_match_phone_with_separators(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.PHONE]
        pattern = patterns[0]

        match = pattern.pattern.search("138-1234-5678")
        assert match is not None
        assert pattern.redact(match.group(0)) == "138****5678"

    def test_redact_phone(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.PHONE]
        pattern = patterns[0]

        assert pattern.redact("13812345678") == "138****5678"
        assert pattern.redact("+8613812345678") == "138****5678"
        assert pattern.redact("138 1234 5678") == "138****5678"

    def test_no_match_invalid_phone(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.PHONE]
        pattern = patterns[0]

        assert pattern.pattern.search("12345678901") is None
        assert pattern.pattern.search("12345") is None


class TestEmailPattern:
    """邮箱检测与脱敏测试。"""

    def test_match_basic_email(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.EMAIL]
        assert len(patterns) == 1
        pattern = patterns[0]

        match = pattern.pattern.search("请联系 support@example.com 获取帮助")
        assert match is not None
        assert match.group(0) == "support@example.com"

    def test_match_complex_email(self):
        patterns = [p for p in get_default_patterns() if p.sensitive_type == SensitiveType.EMAIL]
        pattern = patterns[0]

        match = pattern.pattern.search("zhangsan.2024+tag@company.org")
        assert match is not None

        match = pattern.pattern.search("a_b@mail.test.io")
        assert match is not None

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
