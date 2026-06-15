"""审计清单生成模块。

本模块负责记录所有脱敏操作的详细信息，并支持将审计日志
导出为 JSON、CSV 和 Markdown 等格式，便于合规审查。

高级特性：
- Hash 链可追溯：每条审计记录包含前一条记录的哈希，保证不可篡改
- 完整性校验：通过 Merkle 链风格的 hash 链验证整条审计记录
"""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _compute_hash(data: str) -> str:
    """计算 SHA-256 哈希。"""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


GENESIS_PREV_HASH = "0" * 64


@dataclass
class AuditEntry:
    """单条脱敏审计记录，包含 hash 链信息。

    Attributes:
        line_number: 命中的行号
        sensitive_type: 敏感信息类型（phone/email/...）
        pattern_name: 匹配的规则名称
        original_value: 原始敏感值（脱敏前）
        redacted_value: 脱敏后的值
        start_pos: 在行中的起始位置
        end_pos: 在行中的结束位置
        entry_hash: 本条记录的哈希
        prev_hash: 前一条记录的哈希（hash 链）
        timestamp: 本条记录的时间戳
    """

    line_number: int
    sensitive_type: str
    pattern_name: str
    original_value: str
    redacted_value: str
    start_pos: int
    end_pos: int
    entry_hash: str = ""
    prev_hash: str = ""
    timestamp: str = ""

    def compute_hash(self, prev_hash: str) -> str:
        """基于前一个 hash 计算本条记录的 hash。"""
        payload = (
            f"{prev_hash}|{self.line_number}|{self.sensitive_type}|{self.pattern_name}"
            f"|{self.original_value}|{self.redacted_value}|{self.start_pos}|{self.end_pos}"
            f"|{self.timestamp}"
        )
        return _compute_hash(payload)

    def seal(self, prev_hash: str) -> str:
        """计算并填充哈希值，返回当前 hash 作为下一条的 prev。"""
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        self.prev_hash = prev_hash
        self.entry_hash = self.compute_hash(prev_hash)
        return self.entry_hash

    def verify(self) -> bool:
        """校验本条记录的 hash 是否正确。"""
        expected = self.compute_hash(self.prev_hash)
        return self.entry_hash == expected


class AuditLog:
    """审计日志，聚合所有脱敏操作记录，支持 hash 链完整性校验。

    Attributes:
        source_file: 源文件路径
        output_file: 输出文件路径
        timestamp: 处理时间戳
        entries: 所有脱敏记录
    """

    def __init__(self, enable_hash_chain: bool = True) -> None:
        self.source_file: str = ""
        self.output_file: str = ""
        self.timestamp: datetime = datetime.now()
        self._entries: List[AuditEntry] = []
        self._enable_hash_chain = enable_hash_chain
        self._last_hash: str = GENESIS_PREV_HASH

    @property
    def entries(self) -> List[AuditEntry]:
        """获取所有审计记录（按行号和位置排序）。"""
        return sorted(self._entries, key=lambda x: (x.line_number, x.start_pos))

    @property
    def total_count(self) -> int:
        """脱敏处理总条数。"""
        return len(self._entries)

    @property
    def merkle_root(self) -> str:
        """获取 hash 链的根哈希（最后一条记录的 entry_hash）。"""
        sorted_entries = self.entries
        if not sorted_entries:
            return self._last_hash
        return sorted_entries[-1].entry_hash

    def add_entry(self, entry: AuditEntry) -> None:
        """添加一条审计记录，启用 hash 链时会自动密封。"""
        if self._enable_hash_chain:
            self._last_hash = entry.seal(self._last_hash)
        self._entries.append(entry)

    def verify_chain(self) -> Tuple[bool, List[int]]:
        """校验整条 hash 链的完整性。

        Returns:
            (是否全部有效, 无效记录的索引列表)
        """
        if not self._enable_hash_chain:
            return True, []
        invalid: List[int] = []
        prev_hash = GENESIS_PREV_HASH
        for idx, entry in enumerate(self.entries):
            if entry.prev_hash != prev_hash or not entry.verify():
                invalid.append(idx)
            prev_hash = entry.entry_hash if entry.entry_hash else prev_hash
        return (len(invalid) == 0), invalid

    def finalize(self) -> None:
        """在批量添加后对未密封的记录进行统一密封。

        用于并发处理后合并分片时重建 hash 链。
        """
        if not self._enable_hash_chain:
            return
        prev_hash = GENESIS_PREV_HASH
        for entry in self.entries:
            prev_hash = entry.seal(prev_hash)
        self._last_hash = prev_hash

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
        chain_valid, invalid_indices = audit_log.verify_chain()
        return {
            "source_file": audit_log.source_file,
            "output_file": audit_log.output_file,
            "timestamp": audit_log.timestamp.isoformat(),
            "hash_chain": {
                "enabled": audit_log._enable_hash_chain,
                "valid": chain_valid,
                "merkle_root": audit_log.merkle_root,
                "invalid_indices": invalid_indices,
            },
            "summary": {
                "total_count": audit_log.total_count,
                "by_type": audit_log.count_by_type(),
                "by_pattern": audit_log.count_by_pattern(),
            },
            "entries": [asdict(e) for e in audit_log.entries],
        }

    @staticmethod
    def export_json(audit_log: AuditLog, output_path: Path) -> None:
        """导出为 JSON 格式。"""
        data = AuditExporter.to_dict(audit_log)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def export_csv(audit_log: AuditLog, output_path: Path) -> None:
        """导出为 CSV 格式。"""
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
            "entry_hash",
            "prev_hash",
            "timestamp",
        ]
        with output_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in audit_log.entries:
                writer.writerow(asdict(entry))

    @staticmethod
    def export_markdown(audit_log: AuditLog, output_path: Path) -> None:
        """导出为 Markdown 格式。"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        chain_valid, invalid_indices = audit_log.verify_chain()

        lines: List[str] = []
        lines.append("# 日志脱敏审计报告\n")
        lines.append(f"- **处理时间**: {audit_log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"- **源文件**: `{audit_log.source_file}`")
        lines.append(f"- **输出文件**: `{audit_log.output_file}`")
        if audit_log._enable_hash_chain:
            lines.append(f"- **Hash 链校验**: {'✅ 通过' if chain_valid else '❌ 失败，位置: ' + str(invalid_indices)}")
            lines.append(f"- **Merkle Root**: `{audit_log.merkle_root}`")
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
            if audit_log._enable_hash_chain:
                lines.append(
                    "| 行号 | 类型 | 规则 | 原始值 | 脱敏值 | 位置 | 哈希(前16位) |"
                )
                lines.append("| --- | --- | --- | --- | --- | --- | --- |")
                for entry in audit_log.entries:
                    short_hash = entry.entry_hash[:16] if entry.entry_hash else "-"
                    lines.append(
                        f"| {entry.line_number} | {entry.sensitive_type} | {entry.pattern_name} "
                        f"| `{entry.original_value}` | `{entry.redacted_value}` "
                        f"| [{entry.start_pos}-{entry.end_pos}] | `{short_hash}...` |"
                    )
            else:
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

    @staticmethod
    def verify_json_chain(json_path: Path) -> Tuple[bool, str]:
        """从 JSON 文件加载并校验 hash 链完整性。

        Returns:
            (是否有效, 描述信息)
        """
        json_path = Path(json_path)
        if not json_path.exists():
            return False, f"文件不存在: {json_path}"
        try:
            with json_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return False, f"JSON 解析失败: {e}"

        entries_raw = data.get("entries", [])
        prev_hash = GENESIS_PREV_HASH
        for idx, raw in enumerate(entries_raw):
            entry = AuditEntry(**raw)
            if entry.prev_hash != prev_hash:
                return False, f"第 {idx} 条记录 prev_hash 不匹配"
            if not entry.verify():
                return False, f"第 {idx} 条记录 entry_hash 校验失败"
            prev_hash = entry.entry_hash

        merkle = data.get("hash_chain", {}).get("merkle_root", "")
        if merkle and entries_raw and merkle != entries_raw[-1].get("entry_hash", ""):
            return False, "Merkle Root 不匹配"
        return True, "Hash 链完整有效"
