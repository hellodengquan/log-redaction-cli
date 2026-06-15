"""敏感信息规则定义模块。

本模块定义了各类敏感信息的检测模式和脱敏规则，
目前支持手机号（中国大陆）和邮箱地址的识别与脱敏。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Pattern


class SensitiveType(str, Enum):
    """敏感信息类型枚举。"""

    PHONE = "phone"
    EMAIL = "email"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class SensitivePattern:
    """敏感信息检测模式。

    Attributes:
        name: 模式名称，用于标识
        sensitive_type: 敏感信息类型
        pattern: 正则表达式模式
        redaction_func: 脱敏函数，输入原始值返回脱敏后的值
        description: 模式描述信息
    """

    name: str
    sensitive_type: SensitiveType
    pattern: Pattern[str]
    redaction_func: Callable[[str], str]
    description: str = ""

    def redact(self, value: str) -> str:
        """对匹配到的值进行脱敏处理。"""
        return self.redaction_func(value)


def _redact_phone(match: str) -> str:
    """手机号脱敏：保留前3位和后4位，中间用*替代。

    自动去除 +86/86 等国家代码前缀，取实际手机号部分。
    示例：13812345678 -> 138****5678
    示例：+8613812345678 -> 138****5678
    """
    digits = re.sub(r"\D", "", match)
    if digits.startswith("86") and len(digits) > 11:
        digits = digits[2:]
    if len(digits) > 11:
        digits = digits[-11:]
    if len(digits) < 7:
        return "*" * len(digits)
    prefix = digits[:3]
    suffix = digits[-4:]
    return f"{prefix}****{suffix}"


def _redact_email(match: str) -> str:
    """邮箱脱敏：用户名部分仅保留首字符，其余用*替代，域名保留。

    示例：zhangsan@example.com -> z*******@example.com
    """
    try:
        username, domain = match.split("@", 1)
    except ValueError:
        return "*" * len(match)
    if not username:
        return f"*@{domain}"
    masked_username = username[0] + "*" * (len(username) - 1)
    return f"{masked_username}@{domain}"


_PHONE_PATTERN = re.compile(
    r"(?<!\d)"
    r"(?:\+?86[\s-]?)?"
    r"1[3-9]\d{1}"
    r"[\s-]?\d{4}"
    r"[\s-]?\d{4}"
    r"(?!\d)"
)

_EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)


def get_default_patterns() -> List[SensitivePattern]:
    """获取默认的敏感信息检测模式列表。

    Returns:
        包含手机号和邮箱检测模式的列表
    """
    return [
        SensitivePattern(
            name="china-mobile-phone",
            sensitive_type=SensitiveType.PHONE,
            pattern=_PHONE_PATTERN,
            redaction_func=_redact_phone,
            description="中国大陆手机号码，支持带 +86 前缀及空格/横线分隔符",
        ),
        SensitivePattern(
            name="email-address",
            sensitive_type=SensitiveType.EMAIL,
            pattern=_EMAIL_PATTERN,
            redaction_func=_redact_email,
            description="标准邮箱地址格式",
        ),
    ]
