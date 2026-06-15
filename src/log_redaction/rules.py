"""敏感信息规则定义模块。

本模块定义了各类敏感信息的检测模式和脱敏规则。
支持的功能：
- 手机号（中国大陆、美国、欧盟等多国）
- 邮箱（通用格式）
- 身份证号（中国大陆 18 位）
- 银行卡号
- 中文姓名
- 美国 SSN
- 从 YAML/JSON 配置文件加载规则
- 配置文件 hot reload（检测文件修改自动重新加载
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Pattern


class SensitiveType(str, Enum):
    """敏感信息类型枚举。"""

    PHONE = "phone"
    EMAIL = "email"
    ID_CARD = "id_card"
    BANK_CARD = "bank_card"
    CHINESE_NAME = "chinese_name"
    US_SSN = "us_ssn"
    CUSTOM = "custom"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class SensitivePattern:
    """敏感信息检测模式。

    Attributes:
        name: 模式名称，用于标识
        sensitive_type: 敏感信息类型
        pattern: 正则表达式模式
        redaction_func: 脱敏函数
        description: 模式描述
        lang: 语言/地区标识 (zh-CN, en-US, all 等）
        enabled: 是否启用
    """

    name: str
    sensitive_type: SensitiveType
    pattern: Pattern[str]
    redaction_func: Callable[[str], str]
    description: str = ""
    lang: str = "all"
    enabled: bool = True

    def redact(self, value: str) -> str:
        return self.redaction_func(value)


# ================ 脱敏函数 ================

def _redact_phone_cn(match: str) -> str:
    """中国大陆手机号脱敏：保留前3位和后4位。"""
    digits = re.sub(r"\D", "", match)
    if digits.startswith("86") and len(digits) > 11:
        digits = digits[2:]
    if len(digits) > 11:
        digits = digits[-11:]
    if len(digits) < 7:
        return "*" * len(digits)
    return f"{digits[:3]}****{digits[-4:]}"


def _redact_phone_us(match: str) -> str:
    """美国手机号脱敏：保留后4位。"""
    digits = re.sub(r"\D", "", match)
    if len(digits) < 4:
        return "*" * len(digits)
    return f"***-***-{digits[-4:]}"


def _redact_email(match: str) -> str:
    """邮箱脱敏：用户名仅保留首字符。"""
    try:
        username, domain = match.split("@", 1)
    except ValueError:
        return "*" * len(match)
    if not username:
        return f"*@{domain}"
    masked = username[0] + "*" * (len(username) - 1)
    return f"{masked}@{domain}"


def _redact_id_card_cn(match: str) -> str:
    """中国身份证号脱敏：保留前6位+后4位，中间用*替代。"""
    digits = re.sub(r"[^\dXx]", "", match)
    if len(digits) < 10:
        return "*" * len(digits)
    return f"{digits[:6]}********{digits[-4:]}"


def _redact_bank_card(match: str) -> str:
    """银行卡号脱敏：保留前6位+后4位。"""
    digits = re.sub(r"\D", "", match)
    if len(digits) < 10:
        return "*" * len(digits)
    mid = "*" * (len(digits) - 10)
    return f"{digits[:6]}{mid}{digits[-4:]}"


def _redact_chinese_name(match: str) -> str:
    """中文姓名脱敏：保留姓氏保留，其余用*替代。"""
    s = match.strip()
    if len(s) <= 1:
        return s
    return s[0] + "*" * (len(s) - 1)


def _redact_us_ssn(match: str) -> str:
    """美国 SSN 脱敏：仅保留后4位。"""
    digits = re.sub(r"\D", "", match)
    if len(digits) < 4:
        return "*" * len(digits)
    return f"***-**-{digits[-4:]}"


def _redact_mask_all(match: str) -> str:
    """通用脱敏：全部替换为等长*。"""
    return "*" * len(match)


def _redact_mask_first_half(match: str) -> str:
    """通用脱敏：前半部分打码。"""
    half = len(match) // 2
    return "*" * half + match[half:]


def _redact_mask_last_half(match: str) -> str:
    """通用脱敏：后半部分打码。"""
    half = len(match) // 2
    return match[:half] + "*" * (len(match) - half)


# ================ 脱敏函数注册表 ================

REDACTION_FUNCTIONS: Dict[str, Callable[[str], str]] = {
    "phone_cn": _redact_phone_cn,
    "phone_us": _redact_phone_us,
    "email": _redact_email,
    "id_card_cn": _redact_id_card_cn,
    "bank_card": _redact_bank_card,
    "chinese_name": _redact_chinese_name,
    "us_ssn": _redact_us_ssn,
    "mask_all": _redact_mask_all,
    "mask_first_half": _redact_mask_first_half,
    "mask_last_half": _redact_mask_last_half,
}


def get_redaction_func(name: str) -> Callable[[str], str]:
    """根据名称获取脱敏函数，未知名称返回 mask_all。"""
    return REDACTION_FUNCTIONS.get(name, _redact_mask_all)


# ================ 内置默认模式 ================

_PHONE_CN_PATTERN = re.compile(
    r"(?<!\d)(?:\+?86[\s-]?)?1[3-9]\d[\s-]?\d{4}[\s-]?\d{4}(?!\d)"
)

_PHONE_US_PATTERN = re.compile(
    r"(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
)

_EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

_ID_CARD_CN_PATTERN = re.compile(
    r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"
)

_BANK_CARD_PATTERN = re.compile(
    r"(?<!\d)\d{16,19}(?!\d)"
)

_CHINESE_NAME_PATTERN = re.compile(
    r"(?<![\u4e00-\u9fff])([\u4e00-\u9fff]{2,4})(?![\u4e00-\u9fff])"
)

_US_SSN_PATTERN = re.compile(
    r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"
)


def get_default_patterns() -> List[SensitivePattern]:
    """获取默认内置敏感信息检测模式列表。"""
    return [
        SensitivePattern(
            name="china-mobile-phone",
            sensitive_type=SensitiveType.PHONE,
            pattern=_PHONE_CN_PATTERN,
            redaction_func=_redact_phone_cn,
            description="中国大陆手机号码",
            lang="zh-CN",
            enabled=True,
        ),
        SensitivePattern(
            name="us-mobile-phone",
            sensitive_type=SensitiveType.PHONE,
            pattern=_PHONE_US_PATTERN,
            redaction_func=_redact_phone_us,
            description="美国手机号码",
            lang="en-US",
            enabled=False,
        ),
        SensitivePattern(
            name="email-address",
            sensitive_type=SensitiveType.EMAIL,
            pattern=_EMAIL_PATTERN,
            redaction_func=_redact_email,
            description="标准邮箱地址格式",
            lang="all",
            enabled=True,
        ),
        SensitivePattern(
            name="china-id-card",
            sensitive_type=SensitiveType.ID_CARD,
            pattern=_ID_CARD_CN_PATTERN,
            redaction_func=_redact_id_card_cn,
            description="中国大陆18位身份证号",
            lang="zh-CN",
            enabled=False,
        ),
        SensitivePattern(
            name="bank-card-number",
            sensitive_type=SensitiveType.BANK_CARD,
            pattern=_BANK_CARD_PATTERN,
            redaction_func=_redact_bank_card,
            description="银行卡号(16-19位数字",
            lang="zh-CN",
            enabled=False,
        ),
        SensitivePattern(
            name="chinese-person-name",
            sensitive_type=SensitiveType.CHINESE_NAME,
            pattern=_CHINESE_NAME_PATTERN,
            redaction_func=_redact_chinese_name,
            description="中文姓名(2-4个汉字",
            lang="zh-CN",
            enabled=False,
        ),
        SensitivePattern(
            name="us-social-security-number",
            sensitive_type=SensitiveType.US_SSN,
            pattern=_US_SSN_PATTERN,
            redaction_func=_redact_us_ssn,
            description="美国社会安全号码(SSN)",
            lang="en-US",
            enabled=False,
        ),
    ]


# ================ 配置文件加载与 Hot Reload ================

@dataclass
class RuleConfig:
    """规则配置项。"""
    name: str
    pattern: str
    type: str = "custom"
    redaction: str = "mask_all"
    description: str = ""
    lang: str = "all"
    enabled: bool = True


class RuleConfigLoader:
    """从配置文件加载器，支持 JSON/YAML 格式与 hot reload。

    监听配置文件变更，变更时自动重新加载规则。"""

    SUPPORTED_EXTS = {".json", ".yaml", ".yml"}

    def __init__(self, config_path: Optional[Path] = None, auto_reload: bool = False,
                 poll_interval: float = 2.0) -> None:
        self._config_path: Optional[Path] = Path(config_path) if config_path else None
        self._patterns: List[SensitivePattern] = []
        self._auto_reload = auto_reload
        self._poll_interval = poll_interval
        self._last_mtime: float = 0.0
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._watcher_thread: Optional[threading.Thread] = None
        if self._config_path:
            self.load()
            if auto_reload:
                self._start_watcher()

    @property
    def patterns(self) -> List[SensitivePattern]:
        """返回当前规则列表（只读副本）。"""
        with self._lock:
            return list(self._patterns)

    def _parse_config(self, raw: dict) -> List[SensitivePattern]:
        patterns: List[SensitivePattern] = []
        rules_raw = raw.get("rules", [])
        if not isinstance(rules_raw, list):
            return patterns
        for r in rules_raw:
            try:
                name = r["name"]
                regex = r["pattern"]
                stype_str = r.get("type", "custom").lower()
                try:
                    stype = SensitiveType(stype_str)
                except ValueError:
                    stype = SensitiveType.CUSTOM
                redaction_name = r.get("redaction", "mask_all")
                redaction_func = get_redaction_func(redaction_name)
                description = r.get("description", "")
                lang = r.get("lang", "all")
                enabled = bool(r.get("enabled", True))
                pattern = re.compile(regex)
                patterns.append(
                    SensitivePattern(
                        name=name,
                        sensitive_type=stype,
                        pattern=pattern,
                        redaction_func=redaction_func,
                        description=description,
                        lang=lang,
                        enabled=enabled,
                    )
                )
            except (KeyError, re.error):
                continue
        return patterns

    def load(self, config_path: Optional[Path] = None) -> List[SensitivePattern]:
        """从文件加载规则。"""
        path = Path(config_path) if config_path else self._config_path
        if not path:
            raise ValueError("未指定配置文件路径")
        ext = path.suffix.lower()
        if ext not in self.SUPPORTED_EXTS:
            raise ValueError(f"不支持的配置文件格式: {ext}")
        if not path.exists():
            raise FileNotFoundError(f"配置文件不存在: {path}")
        with path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
        patterns = self._parse_config(raw)
        with self._lock:
            self._patterns = patterns
            self._config_path = path
            self._last_mtime = path.stat().st_mtime
        return patterns

    def reload_if_changed(self) -> bool:
        """检查配置文件如果文件有变更则重新加载。返回是否重新加载。"""
        if not self._config_path or not self._config_path.exists():
            return False
        try:
            mtime = self._config_path.stat().st_mtime
        except OSError:
            return False
        if mtime > self._last_mtime:
            self.load()
            return True
        return False

    def _start_watcher(self) -> None:
        """启动后台线程监听文件变更。"""
        if self._watcher_thread and self._watcher_thread.is_alive():
            return
        self._stop_event.clear()

        def _watch_loop() -> None:
            while not self._stop_event.is_set():
                try:
                    self.reload_if_changed()
                except Exception:
                    pass
                self._stop_event.wait(self._poll_interval)

        self._watcher_thread = threading.Thread(target=_watch_loop, daemon=True)
        self._watcher_thread.start()

    def stop_watcher(self) -> None:
        """停止后台监听线程。"""
        self._stop_event.set()
        if self._watcher_thread and self._watcher_thread.is_alive():
            self._watcher_thread.join(timeout=5)

    def close(self) -> None:
        """关闭资源。"""
        self.stop_watcher()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
