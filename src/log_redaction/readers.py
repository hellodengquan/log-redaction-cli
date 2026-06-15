"""多格式日志 reader 模块。

支持三种日志格式：
- text: 纯文本日志（默认）
- json: JSON Lines 格式，每行一个 JSON 对象
- syslog: Syslog 格式（RFC 3164 / RFC 5424）

每个 reader 解析日志后提取 message 字段进行脱敏，
然后重新组装为原格式输出。
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class LogEntry:
    """统一的日志条目表示。

    Attributes:
        raw: 原始行内容
        fields: 解析出的结构化字段
        message: 需要脱敏的主要消息内容
        line_number: 原始行号
    """

    raw: str
    fields: Dict[str, Any] = field(default_factory=dict)
    message: str = ""
    line_number: int = 0

    def reconstruct(self) -> str:
        """根据原始格式重新组装为字符串。

        由子类实现，默认返回脱敏后的 message。
        """
        return self.message


class LogReader(ABC):
    """日志 reader 抽象基类。"""

    format_name: str = "base"

    @abstractmethod
    def parse_line(self, line: str, line_number: int) -> LogEntry:
        """解析单行日志为 LogEntry。"""

    @abstractmethod
    def format_entry(self, entry: LogEntry, redacted_message: str) -> str:
        """将脱敏后的 LogEntry 重新格式化为字符串。"""

    def read_file(self, path: Path) -> Tuple[List[LogEntry], List[str]]:
        """读取整个文件，返回解析后的条目列表和原始行列表。"""
        path = Path(path)
        entries: List[LogEntry] = []
        raw_lines: List[str] = []
        with path.open("r", encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                raw_lines.append(line)
                stripped = line.rstrip("\n")
                entry = self.parse_line(stripped, idx)
                entry.raw = line
                entries.append(entry)
        return entries, raw_lines

    def process_entries(
        self,
        entries: List[LogEntry],
        redact_func: Callable[[str, int], Tuple[str, List[Any]]],
    ) -> Tuple[List[str], List[Any]]:
        """对所有条目执行脱敏处理。

        Args:
            entries: 日志条目列表
            redact_func: 脱敏函数，签名 (text, line_number) -> (redacted_text, matches)

        Returns:
            (处理后的行列表, 所有匹配项列表)
        """
        output_lines: List[str] = []
        all_matches: List[Any] = []
        for entry in entries:
            redacted_msg, matches = redact_func(entry.message, entry.line_number)
            for m in matches:
                m.line_number = entry.line_number
                all_matches.append(m)
            output_line = self.format_entry(entry, redacted_msg)
            newline = "\n" if entry.raw.endswith("\n") else ""
            output_lines.append(output_line + newline)
        return output_lines, all_matches


class TextReader(LogReader):
    """纯文本日志 reader（默认格式）。

    整行作为 message 处理，脱敏后整行替换。
    """

    format_name = "text"

    def parse_line(self, line: str, line_number: int) -> LogEntry:
        return LogEntry(
            raw=line,
            fields={},
            message=line,
            line_number=line_number,
        )

    def format_entry(self, entry: LogEntry, redacted_message: str) -> str:
        return redacted_message


class JsonLinesReader(LogReader):
    """JSON Lines 格式 reader。

    每行是一个独立的 JSON 对象。默认提取 `message` 字段进行脱敏，
    也可通过 `message_field` 参数指定其他字段。
    """

    format_name = "json"

    def __init__(self, message_field: str = "message") -> None:
        self.message_field = message_field

    def parse_line(self, line: str, line_number: int) -> LogEntry:
        try:
            data = json.loads(line)
            message = str(data.get(self.message_field, ""))
            return LogEntry(
                raw=line,
                fields=data,
                message=message,
                line_number=line_number,
            )
        except json.JSONDecodeError:
            return LogEntry(
                raw=line,
                fields={"_parse_error": True},
                message=line,
                line_number=line_number,
            )

    def format_entry(self, entry: LogEntry, redacted_message: str) -> str:
        if entry.fields.get("_parse_error"):
            return redacted_message
        data = dict(entry.fields)
        data[self.message_field] = redacted_message
        return json.dumps(data, ensure_ascii=False)


# Syslog 正则表达式
# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SDATA] MSG
_SYSLOG_RFC5424_RE = re.compile(
    r"^<(?P<priority>\d+)>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sdata>\[.*?\])?\s*"
    r"(?P<message>.*)$"
)

# RFC 3164 (BSD): <PRI>Mmm dd HH:MM:SS HOSTNAME TAG: MSG
_SYSLOG_RFC3164_RE = re.compile(
    r"^<(?P<priority>\d+)>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<tag>[^:\s]+(?:\[\d+\])?):?\s*"
    r"(?P<message>.*)$"
)


class SyslogReader(LogReader):
    """Syslog 格式 reader。

    自动识别 RFC 5424 和 RFC 3164 两种格式。
    解析出结构化字段后，对 message 部分进行脱敏。
    """

    format_name = "syslog"

    def parse_line(self, line: str, line_number: int) -> LogEntry:
        m = _SYSLOG_RFC5424_RE.match(line)
        if m:
            fields = m.groupdict()
            fields["format"] = "rfc5424"
            return LogEntry(
                raw=line,
                fields=fields,
                message=fields.get("message", ""),
                line_number=line_number,
            )
        m = _SYSLOG_RFC3164_RE.match(line)
        if m:
            fields = m.groupdict()
            fields["format"] = "rfc3164"
            return LogEntry(
                raw=line,
                fields=fields,
                message=fields.get("message", ""),
                line_number=line_number,
            )
        return LogEntry(
            raw=line,
            fields={"_parse_error": True},
            message=line,
            line_number=line_number,
        )

    def format_entry(self, entry: LogEntry, redacted_message: str) -> str:
        if entry.fields.get("_parse_error"):
            return redacted_message
        fmt = entry.fields.get("format")
        if fmt == "rfc5424":
            priority = entry.fields.get("priority", "0")
            version = entry.fields.get("version", "1")
            timestamp = entry.fields.get("timestamp", "-")
            hostname = entry.fields.get("hostname", "-")
            appname = entry.fields.get("appname", "-")
            procid = entry.fields.get("procid", "-")
            msgid = entry.fields.get("msgid", "-")
            sdata = entry.fields.get("sdata") or "-"
            return f"<{priority}>{version} {timestamp} {hostname} {appname} {procid} {msgid} {sdata} {redacted_message}"
        elif fmt == "rfc3164":
            priority = entry.fields.get("priority", "0")
            timestamp = entry.fields.get("timestamp", "")
            hostname = entry.fields.get("hostname", "")
            tag = entry.fields.get("tag", "")
            if tag:
                return f"<{priority}>{timestamp} {hostname} {tag}: {redacted_message}"
            return f"<{priority}>{timestamp} {hostname} {redacted_message}"
        return redacted_message


def get_reader(
    format: str,
    json_message_field: str = "message",
) -> LogReader:
    """工厂函数：根据格式名称获取 reader 实例。

    Args:
        format: 格式名称，可选 'text', 'json', 'syslog'
        json_message_field: JSON 格式的消息字段名

    Returns:
        LogReader 实例

    Raises:
        ValueError: 不支持的格式
    """
    fmt = format.lower().strip()
    if fmt in ("text", "plain", "txt"):
        return TextReader()
    elif fmt in ("json", "jsonl", "ndjson"):
        return JsonLinesReader(message_field=json_message_field)
    elif fmt in ("syslog", "rfc5424", "rfc3164"):
        return SyslogReader()
    else:
        raise ValueError(
            f"不支持的日志格式: {format}。可选格式: text, json, syslog"
        )
