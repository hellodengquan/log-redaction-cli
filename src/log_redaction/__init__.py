"""Log Redaction CLI - 日志脱敏命令行工具包。"""

from .rules import (
    SensitivePattern,
    SensitiveType,
    RuleConfig,
    RuleConfigLoader,
    REDACTION_FUNCTIONS,
    get_default_patterns,
    get_redaction_func,
)
from .redactor import (
    Redactor,
    RedactionResult,
    DEFAULT_CHUNK_LINES,
    DEFAULT_WORKERS,
)
from .audit import (
    AuditLog,
    AuditEntry,
    AuditExporter,
    GENESIS_PREV_HASH,
)
from .crypto import (
    FileEncryptor,
    EncryptionConfig,
    is_encrypted_file,
    encrypt_json_log,
    decrypt_json_log,
)
from .readers import (
    LogReader,
    TextReader,
    JsonLinesReader,
    SyslogReader,
    get_reader,
)

__version__ = "0.3.0"
__all__ = [
    "SensitivePattern",
    "SensitiveType",
    "RuleConfig",
    "RuleConfigLoader",
    "REDACTION_FUNCTIONS",
    "get_default_patterns",
    "get_redaction_func",
    "Redactor",
    "RedactionResult",
    "DEFAULT_CHUNK_LINES",
    "DEFAULT_WORKERS",
    "AuditLog",
    "AuditEntry",
    "AuditExporter",
    "GENESIS_PREV_HASH",
    "FileEncryptor",
    "EncryptionConfig",
    "is_encrypted_file",
    "encrypt_json_log",
    "decrypt_json_log",
    "LogReader",
    "TextReader",
    "JsonLinesReader",
    "SyslogReader",
    "get_reader",
]
