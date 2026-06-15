"""脱敏处理器模块。

本模块负责对日志内容进行扫描，识别敏感信息并执行脱敏处理，
同时记录所有脱敏操作的详细信息用于审计。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

from .audit import AuditEntry, AuditLog
from .rules import SensitivePattern, get_default_patterns


@dataclass
class RedactionResult:
    """单条脱敏操作的结果记录。

    Attributes:
        line_number: 原始行号（从1开始）
        original: 原始内容
        redacted: 脱敏后内容
        matches: 本命中的敏感信息详情列表
    """

    line_number: int
    original: str
    redacted: str
    matches: List[AuditEntry] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """是否发生了脱敏替换。"""
        return self.original != self.redacted


class Redactor:
    """日志脱敏处理器。

    支持对文本、字符串列表和文件进行脱敏处理。

    Args:
        patterns: 自定义敏感模式列表，为空时使用默认模式
    """

    def __init__(self, patterns: Optional[List[SensitivePattern]] = None) -> None:
        self._patterns = patterns if patterns is not None else get_default_patterns()

    @property
    def patterns(self) -> List[SensitivePattern]:
        """当前使用的敏感模式列表。"""
        return list(self._patterns)

    def scan_line(self, line: str, line_number: int = 0) -> RedactionResult:
        """扫描单行内容，识别并脱敏敏感信息。

        Args:
            line: 待处理的文本行
            line_number: 行号，用于审计记录

        Returns:
            RedactionResult 包含原始内容、脱敏内容和匹配详情
        """
        current_text = line
        all_matches: List[AuditEntry] = []

        for pattern in self._patterns:
            new_matches: List[AuditEntry] = []
            for m in pattern.pattern.finditer(current_text):
                original_value = m.group(0)
                redacted_value = pattern.redact(original_value)
                new_matches.append(
                    AuditEntry(
                        line_number=line_number,
                        sensitive_type=str(pattern.sensitive_type),
                        pattern_name=pattern.name,
                        original_value=original_value,
                        redacted_value=redacted_value,
                        start_pos=m.start(),
                        end_pos=m.end(),
                    )
                )
            for match in sorted(new_matches, key=lambda x: x.start_pos, reverse=True):
                current_text = (
                    current_text[: match.start_pos]
                    + match.redacted_value
                    + current_text[match.end_pos :]
                )
                offset = len(match.redacted_value) - len(match.original_value)
                for existing in all_matches:
                    if existing.start_pos >= match.start_pos:
                        existing.start_pos += offset
                        existing.end_pos += offset
            all_matches.extend(new_matches)

        all_matches.sort(key=lambda x: (x.line_number, x.start_pos))
        return RedactionResult(
            line_number=line_number,
            original=line,
            redacted=current_text,
            matches=all_matches,
        )

    def scan_lines(
        self,
        lines: Iterable[str],
        start_line: int = 1,
    ) -> tuple[List[str], AuditLog]:
        """扫描多行内容并执行脱敏。

        Args:
            lines: 文本行迭代器
            start_line: 起始行号

        Returns:
            元组 (脱敏后行列表, 审计日志对象)
        """
        redacted_lines: List[str] = []
        audit_log = AuditLog()

        for idx, line in enumerate(lines):
            line_no = start_line + idx
            original_line = line.rstrip("\n")
            result = self.scan_line(original_line, line_no)
            newline = "\n" if line.endswith("\n") else ""
            redacted_lines.append(result.redacted + newline)
            for match in result.matches:
                audit_log.add_entry(match)

        return redacted_lines, audit_log

    def scan_text(self, text: str) -> tuple[str, AuditLog]:
        """扫描整个文本字符串。

        Args:
            text: 待处理的完整文本

        Returns:
            元组 (脱敏后文本, 审计日志对象)
        """
        lines = text.splitlines(keepends=True)
        redacted_lines, audit_log = self.scan_lines(lines)
        return "".join(redacted_lines), audit_log

    def process_file(
        self,
        input_path: Path,
        output_path: Optional[Path] = None,
        in_place: bool = False,
    ) -> AuditLog:
        """处理日志文件，执行脱敏并生成审计日志。

        Args:
            input_path: 输入日志文件路径
            output_path: 输出文件路径，in_place=True 时忽略
            in_place: 是否原地覆盖输入文件

        Returns:
            审计日志对象

        Raises:
            FileNotFoundError: 输入文件不存在
            ValueError: 未指定 output_path 且 in_place=False
        """
        input_path = Path(input_path)
        if not input_path.is_file():
            raise FileNotFoundError(f"输入文件不存在: {input_path}")

        if not in_place and output_path is None:
            raise ValueError("必须指定 output_path 或设置 in_place=True")

        target_output = input_path if in_place else Path(output_path)

        with input_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()

        redacted_lines, audit_log = self.scan_lines(lines)
        audit_log.source_file = str(input_path.resolve())
        audit_log.output_file = str(target_output.resolve())

        with target_output.open("w", encoding="utf-8") as f:
            f.writelines(redacted_lines)

        return audit_log
