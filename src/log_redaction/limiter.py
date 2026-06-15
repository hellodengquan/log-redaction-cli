"""IO 与内存限额模块。

提供资源限制功能，防止脱敏处理占用过多系统资源：
- 文件大小限额（输入/输出）
- 内存使用限额
- 行数限额（防止超长行导致 OOM）
- 流式文件读取（避免一次性加载大文件）
- 资源超限异常与优雅降级
"""

from __future__ import annotations

import os
import resource
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Tuple


class ResourceLimitExceeded(Exception):
    """资源超限异常。"""

    def __init__(self, resource_type: str, limit: int, actual: int = 0) -> None:
        self.resource_type = resource_type
        self.limit = limit
        self.actual = actual
        msg = f"资源超限: {resource_type} 限制 {limit}"
        if actual:
            msg += f"，实际 {actual}"
        super().__init__(msg)


@dataclass
class ResourceLimits:
    """资源限额配置。

    Attributes:
        max_input_file_size: 输入文件最大字节数 (0=不限)
        max_output_file_size: 输出文件最大字节数 (0=不限)
        max_line_length: 单行最大字节数 (0=不限)
        max_memory_mb: 最大内存使用 MB (0=不限)
        max_lines: 最大处理行数 (0=不限)
        read_buffer_size: 流式读取缓冲区字节数
    """

    max_input_file_size: int = 0
    max_output_file_size: int = 0
    max_line_length: int = 0
    max_memory_mb: int = 0
    max_lines: int = 0
    read_buffer_size: int = 65536

    DEFAULT = None

    @classmethod
    def conservative(cls) -> ResourceLimits:
        return cls(
            max_input_file_size=500 * 1024 * 1024,
            max_output_file_size=500 * 1024 * 1024,
            max_line_length=10 * 1024 * 1024,
            max_memory_mb=512,
            max_lines=0,
            read_buffer_size=65536,
        )

    @classmethod
    def strict(cls) -> ResourceLimits:
        return cls(
            max_input_file_size=50 * 1024 * 1024,
            max_output_file_size=50 * 1024 * 1024,
            max_line_length=1 * 1024 * 1024,
            max_memory_mb=128,
            max_lines=1_000_000,
            read_buffer_size=32768,
        )


ResourceLimits.DEFAULT = ResourceLimits()


class ResourceLimiter:
    """资源限额管理器。

    在脱敏处理流程中强制执行资源限制，
    超限时抛出 ResourceLimitExceeded 异常。
    """

    def __init__(self, limits: Optional[ResourceLimits] = None) -> None:
        self._limits = limits or ResourceLimits()
        self._bytes_read: int = 0
        self._bytes_written: int = 0
        self._lines_processed: int = 0

    @property
    def limits(self) -> ResourceLimits:
        return self._limits

    @property
    def bytes_read(self) -> int:
        return self._bytes_read

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    @property
    def lines_processed(self) -> int:
        return self._lines_processed

    def check_input_file(self, path: Path) -> None:
        path = Path(path)
        if not path.exists():
            return
        size = path.stat().st_size
        if self._limits.max_input_file_size and size > self._limits.max_input_file_size:
            raise ResourceLimitExceeded(
                "输入文件大小",
                self._limits.max_input_file_size,
                size,
            )

    def check_line(self, line: str) -> None:
        self._lines_processed += 1
        line_bytes = len(line.encode("utf-8"))
        self._bytes_read += line_bytes
        if self._limits.max_line_length and line_bytes > self._limits.max_line_length:
            raise ResourceLimitExceeded(
                "单行长度",
                self._limits.max_line_length,
                line_bytes,
            )
        if self._limits.max_lines and self._lines_processed > self._limits.max_lines:
            raise ResourceLimitExceeded(
                "处理行数",
                self._limits.max_lines,
                self._lines_processed,
            )

    def check_output_size(self, size: int) -> None:
        self._bytes_written += size
        if self._limits.max_output_file_size and self._bytes_written > self._limits.max_output_file_size:
            raise ResourceLimitExceeded(
                "输出文件大小",
                self._limits.max_output_file_size,
                self._bytes_written,
            )

    def apply_memory_limit(self) -> None:
        if self._limits.max_memory_mb:
            limit_bytes = self._limits.max_memory_mb * 1024 * 1024
            try:
                soft, hard = resource.getrlimit(resource.RLIMIT_AS)
                new_limit = min(limit_bytes, hard) if hard != resource.RLIM_INFINITY else limit_bytes
                resource.setrlimit(resource.RLIMIT_AS, (new_limit, hard))
            except (ValueError, OSError):
                pass


def stream_lines(
    path: Path,
    limiter: Optional[ResourceLimiter] = None,
    buffer_size: int = 65536,
) -> Iterator[Tuple[int, str]]:
    """流式逐行读取文件，支持资源限额检查。

    Args:
        path: 文件路径
        limiter: 可选的资源限额器
        buffer_size: 读取缓冲区大小

    Yields:
        (行号, 行内容) 元组，行内容保留换行符
    """
    path = Path(path)
    if limiter is not None:
        limiter.check_input_file(path)
    line_number = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_number += 1
            if limiter is not None:
                limiter.check_line(line.rstrip("\n"))
            yield line_number, line


def stream_lines_batch(
    path: Path,
    batch_size: int = 5000,
    limiter: Optional[ResourceLimiter] = None,
) -> Iterator[Tuple[int, List[str]]]:
    """流式批量读取文件行，每批 batch_size 行。

    Args:
        path: 文件路径
        batch_size: 每批行数
        limiter: 可选的资源限额器

    Yields:
        (起始行号, 行列表) 元组
    """
    batch: List[str] = []
    start_line = 1
    for line_no, line in stream_lines(path, limiter=limiter):
        if not batch:
            start_line = line_no
        batch.append(line)
        if len(batch) >= batch_size:
            yield start_line, batch
            batch = []
    if batch:
        yield start_line, batch


def format_size(size_bytes: int) -> str:
    """格式化文件大小为人类可读字符串。"""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}PB"
