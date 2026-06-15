"""多环境配置管理模块。

支持：
- dev/test/prod 等多环境配置切换
- 环境变量覆盖配置
- 配置文件优先级：CLI 参数 > 环境变量 > 配置文件 > 默认值
- YAML/JSON 配置文件格式
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_ENV = "dev"
ENV_VAR_ENV = "LOG_REDACTION_ENV"
ENV_VAR_CONFIG_DIR = "LOG_REDACTION_CONFIG_DIR"


@dataclass
class KmsConfig:
    """KMS 配置。"""

    backend: str = "local"
    password: Optional[str] = None
    key_dir: Optional[str] = None
    key_id: str = "default"
    rotation_days: int = 90


@dataclass
class StorageConfig:
    """存储上传配置。"""

    backend: str = "local"
    archive_dir: Optional[str] = None
    s3_bucket: Optional[str] = None
    s3_prefix: str = "audit-reports/"
    s3_endpoint: Optional[str] = None
    s3_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None


@dataclass
class ResourceConfig:
    """资源限额配置。"""

    max_input_file_size_mb: int = 0
    max_output_file_size_mb: int = 0
    max_line_length: int = 0
    max_memory_mb: int = 0
    max_lines: int = 0


@dataclass
class RulesConfig:
    """规则配置。"""

    config_file: Optional[str] = None
    include_phone: bool = True
    include_email: bool = True
    include_id_card: bool = False
    include_bank_card: bool = False
    include_chinese_name: bool = False
    include_us_ssn: bool = False
    lang: Optional[str] = None
    remote_url: Optional[str] = None
    remote_cache_ttl: int = 3600
    hot_reload: bool = False
    poll_interval: float = 2.0


@dataclass
class OutputConfig:
    """输出配置。"""

    log_format: str = "text"
    json_message_field: str = "message"
    output_format: str = "table"
    encrypt_output: bool = False
    encrypt_audit: bool = False
    audit_format: str = "json"


@dataclass
class PerformanceConfig:
    """性能配置。"""

    workers: int = 0
    chunk_lines: int = 5000


@dataclass
class AppConfig:
    """应用完整配置。"""

    env: str = "dev"
    kms: KmsConfig = field(default_factory=KmsConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    resource: ResourceConfig = field(default_factory=ResourceConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    plugins: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _env_to_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() in ("1", "true", "yes", "on")


def _env_to_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _merge_env_vars(config: AppConfig) -> AppConfig:
    """用环境变量覆盖配置。"""
    env = os.environ.get(ENV_VAR_ENV, config.env)
    config.env = env

    if os.environ.get("LOG_REDACTION_KMS_BACKEND"):
        config.kms.backend = os.environ["LOG_REDACTION_KMS_BACKEND"]
    if os.environ.get("LOG_REDACTION_KMS_PASSWORD"):
        config.kms.password = os.environ["LOG_REDACTION_KMS_PASSWORD"]
    if os.environ.get("LOG_REDACTION_KMS_KEY_DIR"):
        config.kms.key_dir = os.environ["LOG_REDACTION_KMS_KEY_DIR"]
    if os.environ.get("LOG_REDACTION_KMS_KEY_ID"):
        config.kms.key_id = os.environ["LOG_REDACTION_KMS_KEY_ID"]

    if os.environ.get("LOG_REDACTION_STORAGE_BACKEND"):
        config.storage.backend = os.environ["LOG_REDACTION_STORAGE_BACKEND"]
    if os.environ.get("LOG_REDACTION_ARCHIVE_DIR"):
        config.storage.archive_dir = os.environ["LOG_REDACTION_ARCHIVE_DIR"]
    if os.environ.get("LOG_REDACTION_S3_BUCKET"):
        config.storage.s3_bucket = os.environ["LOG_REDACTION_S3_BUCKET"]
    if os.environ.get("LOG_REDACTION_S3_PREFIX"):
        config.storage.s3_prefix = os.environ["LOG_REDACTION_S3_PREFIX"]

    if os.environ.get("LOG_REDACTION_MAX_INPUT_MB"):
        config.resource.max_input_file_size_mb = _env_to_int(
            os.environ["LOG_REDACTION_MAX_INPUT_MB"]
        )
    if os.environ.get("LOG_REDACTION_MAX_OUTPUT_MB"):
        config.resource.max_output_file_size_mb = _env_to_int(
            os.environ["LOG_REDACTION_MAX_OUTPUT_MB"]
        )
    if os.environ.get("LOG_REDACTION_MAX_MEMORY_MB"):
        config.resource.max_memory_mb = _env_to_int(
            os.environ["LOG_REDACTION_MAX_MEMORY_MB"]
        )

    if os.environ.get("LOG_REDACTION_OUTPUT_FORMAT"):
        config.output.output_format = os.environ["LOG_REDACTION_OUTPUT_FORMAT"]
    if os.environ.get("LOG_REDACTION_LOG_FORMAT"):
        config.output.log_format = os.environ["LOG_REDACTION_LOG_FORMAT"]

    if os.environ.get("LOG_REDACTION_WORKERS"):
        config.performance.workers = _env_to_int(
            os.environ["LOG_REDACTION_WORKERS"]
        )

    plugins = os.environ.get("LOG_REDACTION_PLUGINS")
    if plugins:
        config.plugins = [p.strip() for p in plugins.split(",") if p.strip()]

    return config


def _load_config_file(path: Path) -> dict:
    """从文件加载配置，支持 .json 和 .yaml/.yml。"""
    path = Path(path)
    if not path.exists():
        return {}

    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
            return yaml.safe_load(text) or {}
        except ImportError:
            raise ImportError(
                "YAML 配置需要 PyYAML 库，请运行: pip install pyyaml"
            )
    elif path.suffix == ".json":
        return json.loads(text)
    else:
        return {}


def _apply_dict_config(config: AppConfig, data: dict) -> AppConfig:
    """将字典配置应用到 AppConfig。"""
    if "kms" in data and isinstance(data["kms"], dict):
        for k, v in data["kms"].items():
            if hasattr(config.kms, k):
                setattr(config.kms, k, v)
    if "storage" in data and isinstance(data["storage"], dict):
        for k, v in data["storage"].items():
            if hasattr(config.storage, k):
                setattr(config.storage, k, v)
    if "resource" in data and isinstance(data["resource"], dict):
        for k, v in data["resource"].items():
            if hasattr(config.resource, k):
                setattr(config.resource, k, v)
    if "rules" in data and isinstance(data["rules"], dict):
        for k, v in data["rules"].items():
            if hasattr(config.rules, k):
                setattr(config.rules, k, v)
    if "output" in data and isinstance(data["output"], dict):
        for k, v in data["output"].items():
            if hasattr(config.output, k):
                setattr(config.output, k, v)
    if "performance" in data and isinstance(data["performance"], dict):
        for k, v in data["performance"].items():
            if hasattr(config.performance, k):
                setattr(config.performance, k, v)
    if "plugins" in data and isinstance(data["plugins"], list):
        config.plugins = data["plugins"]
    if "extra" in data and isinstance(data["extra"], dict):
        config.extra = data["extra"]
    if "env" in data:
        config.env = data["env"]
    return config


class ConfigManager:
    """多环境配置管理器。"""

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        env: Optional[str] = None,
    ) -> None:
        self._config_dir = Path(config_dir) if config_dir else self._default_config_dir()
        self._env = env or os.environ.get(ENV_VAR_ENV, DEFAULT_ENV)
        self._config: Optional[AppConfig] = None
        self._env_configs: Dict[str, dict] = {}
        self._load_all_configs()

    def _default_config_dir(self) -> Path:
        env_dir = os.environ.get(ENV_VAR_CONFIG_DIR)
        if env_dir:
            return Path(env_dir)
        return Path("./config")

    def _load_all_configs(self) -> None:
        if not self._config_dir.exists():
            return
        for f in self._config_dir.iterdir():
            if f.is_file() and f.suffix in (".json", ".yaml", ".yml"):
                stem = f.stem
                data = _load_config_file(f)
                self._env_configs[stem] = data

    @property
    def env(self) -> str:
        return self._env

    @env.setter
    def env(self, value: str) -> None:
        self._env = value
        self._config = None

    def get_config(self) -> AppConfig:
        """获取当前环境的配置（合并默认+环境配置+环境变量）。"""
        if self._config is not None:
            return self._config

        config = AppConfig(env=self._env)
        base_config = self._env_configs.get("base", {})
        if base_config:
            _apply_dict_config(config, base_config)
        env_config = self._env_configs.get(self._env, {})
        if env_config:
            _apply_dict_config(config, env_config)

        _merge_env_vars(config)
        self._config = config
        return config

    def list_environments(self) -> List[str]:
        """列出所有可用环境。"""
        envs = set(self._env_configs.keys())
        envs.discard("base")
        return sorted(envs)

    def reload(self) -> None:
        """重新加载配置文件。"""
        self._env_configs.clear()
        self._config = None
        self._load_all_configs()

    @property
    def config_dir(self) -> Path:
        return self._config_dir


def get_config_manager(
    config_dir: Optional[Path] = None,
    env: Optional[str] = None,
) -> ConfigManager:
    """获取配置管理器实例（简化函数）。"""
    return ConfigManager(config_dir=config_dir, env=env)
