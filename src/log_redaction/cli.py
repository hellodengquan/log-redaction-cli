"""命令行入口模块。

基于 Typer 构建的 CLI 工具。

子命令（保持原有协议兼容）：
- redact:  对日志文件执行脱敏处理
- scan:    仅扫描敏感信息（不修改文件）
- audit:   生成脱敏审计报告
- verify:  校验审计报告的 hash 链完整性
- rules:   查看已启用的检测规则
"""

from __future__ import annotations

import sys
import dataclasses
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from .audit import AuditExporter, AuditLog
from .redactor import DEFAULT_CHUNK_LINES, DEFAULT_WORKERS, Redactor
from .rules import (
    SensitiveType,
    RuleConfigLoader,
    get_default_patterns,
)

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
    include_id_card: bool = False,
    include_bank_card: bool = False,
    include_chinese_name: bool = False,
    include_us_ssn: bool = False,
    lang: Optional[str] = None,
    config_file: Optional[Path] = None,
    workers: int = 0,
    chunk_lines: int = DEFAULT_CHUNK_LINES,
) -> Redactor:
    """根据参数构建脱敏处理器（保持与原协议兼容并支持扩展）。"""
    patterns = []
    defaults = get_default_patterns()

    def _filter_enabled(p, include_flag: bool, flag_set: bool) -> bool:
        if flag_set:
            return include_flag
        return p.enabled

    flag_map = {
        SensitiveType.PHONE: (include_phone, True),
        SensitiveType.EMAIL: (include_email, True),
        SensitiveType.ID_CARD: (include_id_card, True),
        SensitiveType.BANK_CARD: (include_bank_card, True),
        SensitiveType.CHINESE_NAME: (include_chinese_name, True),
        SensitiveType.US_SSN: (include_us_ssn, True),
    }

    if config_file:
        with RuleConfigLoader(config_file) as loader:
            patterns = [p for p in loader.patterns if p.enabled]
    else:
        for p in defaults:
            include_flag, flag_set = flag_map.get(p.sensitive_type, (False, False))
            if not _filter_enabled(p, include_flag, flag_set):
                continue
            if lang and lang.lower() != "all" and p.lang.lower() != "all":
                if p.lang.lower() != lang.lower():
                    continue
            if flag_set and include_flag and not p.enabled:
                p = dataclasses.replace(p, enabled=True)
            patterns.append(p)

    if not patterns:
        patterns = [p for p in defaults if p.enabled]
    return Redactor(patterns=patterns, workers=workers, chunk_lines=chunk_lines)


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

    chain_valid, invalid = audit_log.verify_chain()
    if chain_valid:
        console.print(f"[green]✓ Hash 链完整性校验通过 (root: {audit_log.merkle_root[:16]}...)[/green]")
    else:
        console.print(f"[red]✗ Hash 链完整性校验失败，异常位置: {invalid}[/red]")

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
    include_id_card: bool = typer.Option(
        False,
        "--id-card/--no-id-card",
        help="是否检测中国大陆身份证号",
    ),
    include_bank_card: bool = typer.Option(
        False,
        "--bank-card/--no-bank-card",
        help="是否检测银行卡号",
    ),
    include_chinese_name: bool = typer.Option(
        False,
        "--chinese-name/--no-chinese-name",
        help="是否检测中文姓名",
    ),
    include_us_ssn: bool = typer.Option(
        False,
        "--us-ssn/--no-us-ssn",
        help="是否检测美国 SSN",
    ),
    lang: Optional[str] = typer.Option(
        None,
        "--lang",
        help="按语言/地区过滤规则 (zh-CN, en-US, all)",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="自定义规则配置文件 (JSON)",
        exists=True,
        file_okay=True,
        dir_okay=False,
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
    workers: int = typer.Option(
        0,
        "--workers",
        "-w",
        help="并发 worker 数（0=自动关闭并发，>=2 启用）",
    ),
    chunk_lines: int = typer.Option(
        DEFAULT_CHUNK_LINES,
        "--chunk-lines",
        help="每分片行数（仅并发模式）",
    ),
) -> None:
    """对日志文件执行脱敏处理。"""
    try:
        redactor = _build_redactor(
            include_phone=include_phone,
            include_email=include_email,
            include_id_card=include_id_card,
            include_bank_card=include_bank_card,
            include_chinese_name=include_chinese_name,
            include_us_ssn=include_us_ssn,
            lang=lang,
            config_file=config_file,
            workers=workers,
            chunk_lines=chunk_lines,
        )
        audit_log = redactor.process_file(
            input_path=input_path,
            output_path=output_path,
            in_place=in_place,
            workers=workers if workers > 0 else None,
            chunk_lines=chunk_lines,
        )
        _print_summary(audit_log)
        _export_audit(audit_log, audit_output, audit_format)
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
    include_id_card: bool = typer.Option(
        False,
        "--id-card/--no-id-card",
        help="是否检测中国大陆身份证号",
    ),
    include_bank_card: bool = typer.Option(
        False,
        "--bank-card/--no-bank-card",
        help="是否检测银行卡号",
    ),
    include_chinese_name: bool = typer.Option(
        False,
        "--chinese-name/--no-chinese-name",
        help="是否检测中文姓名",
    ),
    include_us_ssn: bool = typer.Option(
        False,
        "--us-ssn/--no-us-ssn",
        help="是否检测美国 SSN",
    ),
    lang: Optional[str] = typer.Option(
        None,
        "--lang",
        help="按语言/地区过滤规则 (zh-CN, en-US, all)",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="自定义规则配置文件 (JSON)",
        exists=True,
        file_okay=True,
        dir_okay=False,
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
        redactor = _build_redactor(
            include_phone=include_phone,
            include_email=include_email,
            include_id_card=include_id_card,
            include_bank_card=include_bank_card,
            include_chinese_name=include_chinese_name,
            include_us_ssn=include_us_ssn,
            lang=lang,
            config_file=config_file,
        )
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
            table.add_column("规则", style="blue")
            table.add_column("原始值", style="yellow")
            table.add_column("脱敏值", style="green")
            for entry in audit_log.entries:
                table.add_row(
                    str(entry.line_number),
                    entry.sensitive_type,
                    entry.pattern_name,
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
    include_id_card: bool = typer.Option(
        False,
        "--id-card/--no-id-card",
        help="是否检测身份证号",
    ),
    include_bank_card: bool = typer.Option(
        False,
        "--bank-card/--no-bank-card",
        help="是否检测银行卡号",
    ),
    include_chinese_name: bool = typer.Option(
        False,
        "--chinese-name/--no-chinese-name",
        help="是否检测中文姓名",
    ),
    include_us_ssn: bool = typer.Option(
        False,
        "--us-ssn/--no-us-ssn",
        help="是否检测美国 SSN",
    ),
    lang: Optional[str] = typer.Option(
        None,
        "--lang",
        help="按语言/地区过滤规则",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="自定义规则配置文件",
        exists=True,
    ),
    workers: int = typer.Option(
        0,
        "--workers",
        "-w",
        help="并发 worker 数",
    ),
) -> None:
    """生成脱敏审计报告（不修改原文件）。"""
    try:
        redactor = _build_redactor(
            include_phone=include_phone,
            include_email=include_email,
            include_id_card=include_id_card,
            include_bank_card=include_bank_card,
            include_chinese_name=include_chinese_name,
            include_us_ssn=include_us_ssn,
            lang=lang,
            config_file=config_file,
            workers=workers,
        )
        with input_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        if workers > 1:
            _, audit_log = redactor.scan_lines_parallel(lines, workers=workers)
        else:
            _, audit_log = redactor.scan_lines(lines)
        audit_log.source_file = str(input_path.resolve())
        audit_log.output_file = str(output_path.resolve())
        _export_audit(audit_log, output_path, format)
        _print_summary(audit_log)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]✗ 错误: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("verify")
def verify(
    audit_path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="审计报告 JSON 文件路径",
    ),
) -> None:
    """校验审计报告的 hash 链完整性。"""
    valid, message = AuditExporter.verify_json_chain(audit_path)
    if valid:
        console.print(f"[green]✓ {message}[/green]")
        raise typer.Exit(code=0)
    else:
        console.print(f"[red]✗ {message}[/red]")
        raise typer.Exit(code=2)


@app.command("rules")
def list_rules(
    lang: Optional[str] = typer.Option(
        None,
        "--lang",
        help="按语言/地区过滤 (zh-CN, en-US, all)",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="加载自定义配置文件中的规则",
        exists=True,
    ),
    show_all: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="显示全部规则（包括默认禁用的）",
    ),
) -> None:
    """查看当前可用的敏感信息检测规则。"""
    if config_file:
        with RuleConfigLoader(config_file) as loader:
            patterns = loader.patterns
    else:
        patterns = get_default_patterns()

    if lang and lang.lower() != "all":
        patterns = [p for p in patterns if p.lang.lower() == "all" or p.lang.lower() == lang.lower()]
    if not show_all:
        patterns = [p for p in patterns if p.enabled]

    table = Table(title="可用检测规则")
    table.add_column("规则名称", style="cyan")
    table.add_column("类型", style="magenta")
    table.add_column("语言/地区", style="blue")
    table.add_column("状态", style="green")
    table.add_column("描述", style="yellow")
    for p in patterns:
        status = "[green]启用[/green]" if p.enabled else "[dim]禁用[/dim]"
        table.add_row(p.name, str(p.sensitive_type), p.lang, status, p.description)
    console.print(table)


def main() -> None:
    """程序入口函数。"""
    app()


if __name__ == "__main__":
    main()
