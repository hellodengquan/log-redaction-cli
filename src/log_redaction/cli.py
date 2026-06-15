"""命令行入口模块。

基于 Typer 构建的 CLI 工具，提供以下子命令：
- redact: 对日志文件执行脱敏处理
- scan:   仅扫描敏感信息（不修改文件）
- audit:  生成脱敏审计报告
- rules:  查看已启用的检测规则
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .audit import AuditExporter, AuditLog
from .redactor import Redactor
from .rules import SensitiveType, get_default_patterns

app = typer.Typer(
    help="日志脱敏 CLI 工具 - 扫描并脱敏日志中的手机号、邮箱等敏感信息",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

AUDIT_FORMATS = ["json", "csv", "markdown"]


def _build_redactor(
    include_phone: bool,
    include_email: bool,
) -> Redactor:
    """根据参数构建脱敏处理器。"""
    patterns = []
    defaults = get_default_patterns()
    for p in defaults:
        if p.sensitive_type == SensitiveType.PHONE and include_phone:
            patterns.append(p)
        if p.sensitive_type == SensitiveType.EMAIL and include_email:
            patterns.append(p)
    if not patterns:
        patterns = defaults
    return Redactor(patterns)


def _print_summary(audit_log: AuditLog) -> None:
    """使用 rich 输出处理摘要表格。"""
    total = audit_log.total_count
    by_type = audit_log.count_by_type()

    console.print()
    if total == 0:
        console.print("[green]✓ 未检测到敏感信息[/green]")
        return

    console.print(f"[yellow]⚠ 共检测并脱敏 {total} 条敏感信息[/yellow]")
    table = Table(title="脱敏统计")
    table.add_column("类型", style="cyan")
    table.add_column("数量", style="magenta", justify="right")
    for stype, count in sorted(by_type.items()):
        table.add_row(stype, str(count))
    console.print(table)

    if audit_log.source_file:
        console.print(f"[dim]源文件: {audit_log.source_file}[/dim]")
    if audit_log.output_file:
        console.print(f"[dim]输出:   {audit_log.output_file}[/dim]")


def _export_audit(
    audit_log: AuditLog,
    output_path: Optional[Path],
    fmt: str,
) -> None:
    """根据格式导出审计报告。"""
    if output_path is None:
        return
    fmt = fmt.lower()
    if fmt == "json":
        AuditExporter.export_json(audit_log, output_path)
    elif fmt == "csv":
        AuditExporter.export_csv(audit_log, output_path)
    elif fmt == "markdown":
        AuditExporter.export_markdown(audit_log, output_path)
    else:
        raise typer.BadParameter(f"不支持的审计格式: {fmt}")
    console.print(f"[green]✓ 审计报告已导出至: {output_path}[/green]")


@app.command("redact")
def redact(
    input_path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="输入日志文件路径",
    ),
    output_path: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="输出文件路径，未指定时需使用 --in-place",
    ),
    in_place: bool = typer.Option(
        False,
        "--in-place",
        "-i",
        help="原地覆盖输入文件",
    ),
    include_phone: bool = typer.Option(
        True,
        "--phone/--no-phone",
        help="是否检测手机号",
    ),
    include_email: bool = typer.Option(
        True,
        "--email/--no-email",
        help="是否检测邮箱",
    ),
    audit_output: Optional[Path] = typer.Option(
        None,
        "--audit",
        "-a",
        help="审计报告输出路径",
    ),
    audit_format: str = typer.Option(
        "json",
        "--audit-format",
        "-f",
        help=f"审计报告格式，可选: {', '.join(AUDIT_FORMATS)}",
    ),
) -> None:
    """对日志文件执行脱敏处理。"""
    try:
        redactor = _build_redactor(include_phone, include_email)
        audit_log = redactor.process_file(
            input_path=input_path,
            output_path=output_path,
            in_place=in_place,
        )
        _print_summary(audit_log)
        _export_audit(audit_log, audit_output, audit_format)
        sys.exit(0 if audit_log.total_count == 0 else 0)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]✗ 错误: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("scan")
def scan(
    input_path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="输入日志文件路径",
    ),
    include_phone: bool = typer.Option(
        True,
        "--phone/--no-phone",
        help="是否检测手机号",
    ),
    include_email: bool = typer.Option(
        True,
        "--email/--no-email",
        help="是否检测邮箱",
    ),
    show_lines: bool = typer.Option(
        False,
        "--show-lines",
        "-l",
        help="显示命中的原始行内容",
    ),
) -> None:
    """仅扫描敏感信息，不修改文件内容。"""
    try:
        redactor = _build_redactor(include_phone, include_email)
        with input_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        _, audit_log = redactor.scan_lines(lines)
        audit_log.source_file = str(input_path.resolve())
        _print_summary(audit_log)

        if show_lines and audit_log.entries:
            console.print()
            table = Table(title="命中详情")
            table.add_column("行号", style="cyan", justify="right")
            table.add_column("类型", style="magenta")
            table.add_column("原始值", style="yellow")
            table.add_column("脱敏值", style="green")
            for entry in audit_log.entries:
                table.add_row(
                    str(entry.line_number),
                    entry.sensitive_type,
                    entry.original_value,
                    entry.redacted_value,
                )
            console.print(table)
    except FileNotFoundError as e:
        console.print(f"[red]✗ 错误: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("audit")
def audit_cmd(
    input_path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="输入日志文件路径",
    ),
    output_path: Path = typer.Argument(
        ...,
        help="审计报告输出路径",
    ),
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help=f"报告格式，可选: {', '.join(AUDIT_FORMATS)}",
    ),
    include_phone: bool = typer.Option(
        True,
        "--phone/--no-phone",
        help="是否检测手机号",
    ),
    include_email: bool = typer.Option(
        True,
        "--email/--no-email",
        help="是否检测邮箱",
    ),
) -> None:
    """生成脱敏审计报告（不修改原文件）。"""
    try:
        redactor = _build_redactor(include_phone, include_email)
        audit_log = AuditLog()
        audit_log.source_file = str(input_path.resolve())

        with input_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()

        redacted_lines, audit_log = redactor.scan_lines(lines)
        audit_log.source_file = str(input_path.resolve())
        audit_log.output_file = str(output_path.resolve())

        _export_audit(audit_log, output_path, format)
        _print_summary(audit_log)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]✗ 错误: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("rules")
def list_rules() -> None:
    """查看当前可用的敏感信息检测规则。"""
    patterns = get_default_patterns()
    table = Table(title="可用检测规则")
    table.add_column("规则名称", style="cyan")
    table.add_column("类型", style="magenta")
    table.add_column("描述", style="green")
    for p in patterns:
        table.add_row(p.name, str(p.sensitive_type), p.description)
    console.print(table)


def main() -> None:
    """程序入口函数。"""
    app()


if __name__ == "__main__":
    main()
