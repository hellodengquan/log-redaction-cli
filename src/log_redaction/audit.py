"""审计清单生成模块。

本模块负责记录所有脱敏操作的详细信息，并支持将审计日志
导出为 JSON、CSV 和 Markdown 等格式，便于合规审查。
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class AuditEntry:
    """单条脱敏审计记录。

    Attributes:
        line_number: 命中的行号
        sensitive_type: 敏感信息类型（phone/email）
        pattern_name: 匹配的规则名称
        original_value: 原始敏感值（脱敏前）
        redacted_value: 脱敏后的值
        start_pos: 在行中的起始位置
        end_pos: 在行中的结束位置
    """

    line_number: int
    sensitive_type: str
    pattern_name: str
    original_value: str
    redacted_value: str
    start_pos: int
    end_pos: int


class AuditLog:
    """审计日志，聚合所有脱敏操作记录。

    Attributes:
        source_file: 源文件路径
        output_file: 输出文件路径
        timestamp: 处理时间戳
        entries: 所有脱敏记录
    """

    def __init__(self) -> None:
        self.source_file: str = ""
        self.output_file: str = ""
        self.timestamp: datetime = datetime.now()
        self._entries: List[AuditEntry] = []

    @property
    def entries(self) -> List[AuditEntry]:
        """获取所有审计记录（按行号和位置排序）。"""
        return sorted(self._entries, key=lambda x: (x.line_number, x.start_pos))

    @property
    def total_count(self) -> int:
        """脱敏处理总条数。"""
        return len(self._entries)

    def add_entry(self, entry: AuditEntry) -> None:
        """添加一条审计记录。"""
        self._entries.append(entry)

    def count_by_type(self) -> Dict[str, int]:
        """按敏感类型统计数量。"""
        result: Dict[str, int] = {}
        for entry in self._entries:
            result[entry.sensitive_type] = result.get(entry.sensitive_type, 0) + 1
        return result

    def count_by_pattern(self) -> Dict[str, int]:
        """按规则名称统计数量。"""
        result: Dict[str, int] = {}
        for entry in self._entries:
            result[entry.pattern_name] = result.get(entry.pattern_name, 0) + 1
        return result

    def count_by_line(self) -> Dict[int, int]:
        """按行号统计命中数量。"""
        result: Dict[int, int] = {}
        for entry in self._entries:
            result[entry.line_number] = result.get(entry.line_number, 0) + 1
        return result


class AuditExporter:
    """审计日志导出器。

    支持将审计日志导出为 JSON、CSV 和 Markdown 格式。
    """

    @staticmethod
    def to_dict(audit_log: AuditLog) -> dict:
        """将审计日志转换为字典结构。"""
        return {
            "source_file": audit_log.source_file,
            "output_file": audit_log.output_file,
            "timestamp": audit_log.timestamp.isoformat(),
            "summary": {
                "total_count": audit_log.total_count,
                "by_type": audit_log.count_by_type(),
                "by_pattern": audit_log.count_by_pattern(),
            },
            "entries": [asdict(e) for e in audit_log.entries],
        }

    @staticmethod
    def export_json(audit_log: AuditLog, output_path: Path) -> None:
        """导出为 JSON 格式。

        Args:
            audit_log: 审计日志对象
            output_path: 输出文件路径
        """
        data = AuditExporter.to_dict(audit_log)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def export_csv(audit_log: AuditLog, output_path: Path) -> None:
        """导出为 CSV 格式。

        Args:
            audit_log: 审计日志对象
            output_path: 输出文件路径
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "line_number",
            "sensitive_type",
            "pattern_name",
            "original_value",
            "redacted_value",
            "start_pos",
            "end_pos",
        ]
        with output_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in audit_log.entries:
                writer.writerow(asdict(entry))

    @staticmethod
    def export_markdown(audit_log: AuditLog, output_path: Path) -> None:
        """导出为 Markdown 格式。

        Args:
            audit_log: 审计日志对象
            output_path: 输出文件路径
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        lines: List[str] = []
        lines.append("# 日志脱敏审计报告\n")
        lines.append(f"- **处理时间**: {audit_log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"- **源文件**: `{audit_log.source_file}`")
        lines.append(f"- **输出文件**: `{audit_log.output_file}`")
        lines.append("")

        lines.append("## 统计概览\n")
        lines.append(f"- **脱敏总条数**: {audit_log.total_count}")
        lines.append("")

        by_type = audit_log.count_by_type()
        if by_type:
            lines.append("### 按敏感类型统计\n")
            lines.append("| 类型 | 数量 |")
            lines.append("| --- | --- |")
            for stype, count in sorted(by_type.items()):
                lines.append(f"| {stype} | {count} |")
            lines.append("")

        by_pattern = audit_log.count_by_pattern()
        if by_pattern:
            lines.append("### 按规则统计\n")
            lines.append("| 规则名称 | 数量 |")
            lines.append("| --- | --- |")
            for pname, count in sorted(by_pattern.items()):
                lines.append(f"| {pname} | {count} |")
            lines.append("")

        if audit_log.entries:
            lines.append("## 详细记录\n")
            lines.append(
                "| 行号 | 类型 | 规则 | 原始值 | 脱敏值 | 位置 |"
            )
            lines.append("| --- | --- | --- | --- | --- | --- |")
            for entry in audit_log.entries:
                lines.append(
                    f"| {entry.line_number} | {entry.sensitive_type} | {entry.pattern_name} "
                    f"| `{entry.original_value}` | `{entry.redacted_value}` "
                    f"| [{entry.start_pos}-{entry.end_pos}] |"
                )
            lines.append("")

        with output_path.open("w", encoding="utf-8") as f:
            f.write("\n".join(lines))
