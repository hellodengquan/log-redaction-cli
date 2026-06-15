"""脱敏处理器模块。

本模块负责对日志内容进行扫描，识别敏感信息并执行脱敏处理，
同时记录所有脱敏操作的详细信息用于审计。

高级特性：
- 大日志文件按行分片 + 多进程并发处理
- 兼容 RuleConfigLoader 动态规则
"""

from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .audit import AuditEntry, AuditLog
from .crypto import EncryptionConfig, FileEncryptor
from .limiter import ResourceLimiter, ResourceLimitExceeded
from .readers import LogReader, get_reader
from .rules import SensitivePattern, get_default_patterns


DEFAULT_CHUNK_LINES = 5000
DEFAULT_WORKERS = max(2, (os.cpu_count() or 2) - 1)


@dataclass
class _ChunkTask:
    """分片任务定义。"""

    chunk_id: int
    start_line: int
    lines: List[str]


@dataclass
class _ChunkResult:
    """分片处理结果。"""

    chunk_id: int
    start_line: int
    redacted_lines: List[str]
    entries: List[AuditEntry]


@dataclass
class RedactionResult:
    """单条脱敏操作的结果记录。"""

    line_number: int
    original: str
    redacted: str
    matches: List[AuditEntry] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return self.original != self.redacted


def _process_chunk(
    task: _ChunkTask,
    patterns_data: List[dict],
) -> _ChunkResult:
    """进程池工作函数：处理单个分片。

    由于进程间不能传递正则 compiled pattern 对象，
    这里传递原始 pattern 数据在子进程中重新编译。
    """
    from .rules import REDACTION_FUNCTIONS, SensitiveType, SensitivePattern, get_redaction_func
    import re as _re

    local_patterns: List[SensitivePattern] = []
    for pd in patterns_data:
        try:
            stype = SensitiveType(pd["sensitive_type"])
        except ValueError:
            stype = SensitiveType.CUSTOM
        redaction_name = pd.get("redaction_name", "mask_all")
        redaction_func = get_redaction_func(redaction_name)
        pattern = SensitivePattern(
            name=pd["name"],
            sensitive_type=stype,
            pattern=_re.compile(pd["regex"]),
            redaction_func=redaction_func,
            description=pd.get("description", ""),
            lang=pd.get("lang", "all"),
            enabled=bool(pd.get("enabled", True)),
        )
        local_patterns.append(pattern)

    redacted_lines: List[str] = []
    all_entries: List[AuditEntry] = []

    for offset, line in enumerate(task.lines):
        line_no = task.start_line + offset
        original_line = line.rstrip("\n")
        current_text = original_line
        matches_in_line: List[AuditEntry] = []

        for p in local_patterns:
            if not p.enabled:
                continue
            new_matches: List[AuditEntry] = []
            for m in p.pattern.finditer(current_text):
                original_value = m.group(0)
                redacted_value = p.redact(original_value)
                new_matches.append(
                    AuditEntry(
                        line_number=line_no,
                        sensitive_type=str(p.sensitive_type),
                        pattern_name=p.name,
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
                off = len(match.redacted_value) - len(match.original_value)
                for existing in matches_in_line:
                    if existing.start_pos >= match.start_pos:
                        existing.start_pos += off
                        existing.end_pos += off
            matches_in_line.extend(new_matches)

        newline = "\n" if line.endswith("\n") else ""
        redacted_lines.append(current_text + newline)
        all_entries.extend(matches_in_line)

    return _ChunkResult(
        chunk_id=task.chunk_id,
        start_line=task.start_line,
        redacted_lines=redacted_lines,
        entries=all_entries,
    )


class Redactor:
    """日志脱敏处理器。

    支持对文本、字符串列表和文件进行脱敏处理。
    大文件可通过 workers > 1 启用并发模式。

    Args:
        patterns: 自定义敏感模式列表，为空时使用默认模式
        workers: 并发 worker 数，0 或 1 表示串行处理
        chunk_lines: 每个分片的行数（仅并发模式使用）
    """

    def __init__(
        self,
        patterns: Optional[List[SensitivePattern]] = None,
        workers: int = 0,
        chunk_lines: int = DEFAULT_CHUNK_LINES,
        log_format: str = "text",
        json_message_field: str = "message",
        encryption_config: Optional[EncryptionConfig] = None,
    ) -> None:
        self._patterns = patterns if patterns is not None else [
            p for p in get_default_patterns() if p.enabled
        ]
        self._workers = max(0, workers)
        self._chunk_lines = max(100, chunk_lines)
        self._log_format = log_format
        self._json_message_field = json_message_field
        self._reader: LogReader = get_reader(log_format, json_message_field)
        self._encryption_config = encryption_config
        self._encryptor: Optional[FileEncryptor] = (
            FileEncryptor(encryption_config) if encryption_config else None
        )

    @property
    def patterns(self) -> List[SensitivePattern]:
        return list(self._patterns)

    def set_patterns(self, patterns: List[SensitivePattern]) -> None:
        """动态更新规则（用于 hot reload）。"""
        self._patterns = list(patterns)

    def scan_line(self, line: str, line_number: int = 0) -> RedactionResult:
        """扫描单行内容，识别并脱敏敏感信息。"""
        current_text = line
        all_matches: List[AuditEntry] = []

        for pattern in self._patterns:
            if not pattern.enabled:
                continue
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
    ) -> Tuple[List[str], AuditLog]:
        """扫描多行内容并执行脱敏（串行）。"""
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

    def scan_lines_parallel(
        self,
        lines: List[str],
        start_line: int = 1,
        workers: Optional[int] = None,
        chunk_lines: Optional[int] = None,
    ) -> Tuple[List[str], AuditLog]:
        """按行分片并发扫描。

        Args:
            lines: 待处理的行列表
            start_line: 起始行号
            workers: 并发进程数，默认使用初始化时的 workers
            chunk_lines: 每分片行数，默认使用初始化值

        Returns:
            (脱敏后行列表, 审计日志)
        """
        num_workers = workers if workers is not None else self._workers
        num_workers = max(1, num_workers)
        cl = chunk_lines if chunk_lines is not None else self._chunk_lines
        cl = max(100, cl)

        if num_workers <= 1 or len(lines) <= cl:
            return self.scan_lines(lines, start_line)

        tasks: List[_ChunkTask] = []
        chunk_id = 0
        cursor = 0
        while cursor < len(lines):
            end = min(cursor + cl, len(lines))
            tasks.append(
                _ChunkTask(
                    chunk_id=chunk_id,
                    start_line=start_line + cursor,
                    lines=lines[cursor:end],
                )
            )
            cursor = end
            chunk_id += 1

        patterns_data = [
            {
                "name": p.name,
                "sensitive_type": str(p.sensitive_type),
                "regex": p.pattern.pattern,
                "redaction_name": self._resolve_redaction_name(p.redaction_func),
                "description": p.description,
                "lang": p.lang,
                "enabled": p.enabled,
            }
            for p in self._patterns
        ]

        results: List[_ChunkResult] = []
        if num_workers == 1:
            for t in tasks:
                results.append(_process_chunk(t, patterns_data))
        else:
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                futures = [executor.submit(_process_chunk, t, patterns_data) for t in tasks]
                for fut in as_completed(futures):
                    results.append(fut.result())

        results.sort(key=lambda r: r.chunk_id)

        final_lines: List[str] = []
        audit_log = AuditLog()
        for r in results:
            final_lines.extend(r.redacted_lines)
            for e in r.entries:
                audit_log.add_entry(e)
        audit_log.finalize()
        return final_lines, audit_log

    def _resolve_redaction_name(self, func) -> str:
        """根据函数引用反向查找脱敏函数名称。"""
        from .rules import REDACTION_FUNCTIONS
        for name, f in REDACTION_FUNCTIONS.items():
            if f is func:
                return name
        return "mask_all"

    def scan_text(self, text: str) -> Tuple[str, AuditLog]:
        """扫描整个文本字符串。"""
        lines = text.splitlines(keepends=True)
        redacted_lines, audit_log = self.scan_lines(lines)
        return "".join(redacted_lines), audit_log

    def process_file(
        self,
        input_path: Path,
        output_path: Optional[Path] = None,
        in_place: bool = False,
        workers: Optional[int] = None,
        chunk_lines: Optional[int] = None,
        log_format: Optional[str] = None,
        json_message_field: Optional[str] = None,
        encrypt_output: bool = False,
        encrypt_audit: bool = False,
        encryption_password: Optional[str] = None,
        resource_limiter: Optional[ResourceLimiter] = None,
    ) -> AuditLog:
        """处理日志文件，执行脱敏并生成审计日志。"""
        input_path = Path(input_path)
        if not input_path.is_file():
            raise FileNotFoundError(f"输入文件不存在: {input_path}")

        if not in_place and output_path is None:
            raise ValueError("必须指定 output_path 或设置 in_place=True")

        if resource_limiter is not None:
            resource_limiter.check_input_file(input_path)

        target_output = input_path if in_place else Path(output_path)

        if log_format is not None:
            self._log_format = log_format
            self._json_message_field = (
                json_message_field
                if json_message_field is not None
                else self._json_message_field
            )
            self._reader = get_reader(self._log_format, self._json_message_field)

        encryptor: Optional[FileEncryptor] = None
        if encryption_password is not None:
            encrypt_config = EncryptionConfig(password=encryption_password)
            encryptor = FileEncryptor(encrypt_config)
        elif self._encryptor is not None:
            encryptor = self._encryptor

        entries, raw_lines = self._reader.read_file(input_path)
        messages = [e.message for e in entries]

        if resource_limiter is not None:
            for msg in messages:
                resource_limiter.check_line(msg)

        num_workers = workers if workers is not None else self._workers
        if num_workers and num_workers > 1 and len(messages) > self._chunk_lines:
            redacted_messages, audit_log = self.scan_lines_parallel(
                messages, workers=num_workers, chunk_lines=chunk_lines
            )
        else:
            redacted_messages, audit_log = self.scan_lines(messages)

        audit_log.source_file = str(input_path.resolve())
        audit_log.output_file = str(target_output.resolve())
        audit_log.finalize()

        output_lines = []
        for entry, redacted_msg in zip(entries, redacted_messages):
            formatted = self._reader.format_entry(entry, redacted_msg.rstrip("\n"))
            newline = "\n" if entry.raw.endswith("\n") else ""
            output_lines.append(formatted + newline)

        output_content = "".join(output_lines).encode("utf-8")
        if resource_limiter is not None:
            resource_limiter.check_output_size(len(output_content))
        if encrypt_output and encryptor is not None:
            output_content = encryptor.encrypt_bytes(output_content)
            with target_output.open("wb") as f:
                f.write(output_content)
        else:
            with target_output.open("w", encoding="utf-8") as f:
                f.writelines(output_lines)

        if encrypt_audit and encryptor is not None:
            audit_log._encryptor = encryptor

        return audit_log

    def process_file_with_reader(
        self,
        input_path: Path,
        reader: LogReader,
        output_path: Optional[Path] = None,
        in_place: bool = False,
        workers: Optional[int] = None,
        chunk_lines: Optional[int] = None,
        encryptor: Optional[FileEncryptor] = None,
        encrypt_output: bool = False,
    ) -> AuditLog:
        """使用自定义 reader 处理文件（高级 API）。"""
        self._reader = reader
        return self.process_file(
            input_path=input_path,
            output_path=output_path,
            in_place=in_place,
            workers=workers,
            chunk_lines=chunk_lines,
            encrypt_output=encrypt_output,
            encryption_password=None,
        )
