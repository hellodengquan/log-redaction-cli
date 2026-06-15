"""敏感词规则远端同步模块。

支持：
- 从 HTTP/HTTPS URL 拉取规则配置（JSON/YAML）
- 本地缓存（带版本号和时间戳）
- 缓存 TTL，自动过期
- 手动触发同步
- 拉取失败时降级使用本地缓存
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .rules import SensitivePattern


@dataclass
class RemoteRulesCache:
    """远端规则缓存元数据。"""

    version: str = ""
    url: str = ""
    fetched_at: float = 0.0
    ttl: int = 3600
    etag: str = ""
    checksum_sha256: str = ""
    rules_count: int = 0

    @property
    def is_expired(self) -> bool:
        if self.ttl <= 0:
            return False
        return (time.time() - self.fetched_at) > self.ttl

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": self.version,
                "url": self.url,
                "fetched_at": self.fetched_at,
                "ttl": self.ttl,
                "etag": self.etag,
                "checksum_sha256": self.checksum_sha256,
                "rules_count": self.rules_count,
            },
            ensure_ascii=False,
            indent=2,
        )

    @classmethod
    def from_json(cls, text: str) -> "RemoteRulesCache":
        try:
            data = json.loads(text)
            return cls(
                version=data.get("version", ""),
                url=data.get("url", ""),
                fetched_at=data.get("fetched_at", 0.0),
                ttl=data.get("ttl", 3600),
                etag=data.get("etag", ""),
                checksum_sha256=data.get("checksum_sha256", ""),
                rules_count=data.get("rules_count", 0),
            )
        except (json.JSONDecodeError, TypeError):
            return cls()


class RemoteRulesSyncer:
    """远端规则同步器。

    从远程 URL 拉取规则配置，支持本地缓存和 TTL 过期。
    """

    DEFAULT_TIMEOUT = 30

    def __init__(
        self,
        url: str,
        cache_dir: Optional[Path] = None,
        ttl: int = 3600,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._url = url
        self._cache_dir = Path(cache_dir) if cache_dir else Path(tempfile.gettempdir()) / "log-redaction-rules"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._ttl = ttl
        self._timeout = timeout
        self._cache_meta = RemoteRulesCache(url=url, ttl=ttl)
        self._cache_file = self._cache_dir / "rules.json"
        self._meta_file = self._cache_dir / "cache_meta.json"
        self._load_cache_meta()

    def _load_cache_meta(self) -> None:
        if self._meta_file.exists():
            try:
                self._cache_meta = RemoteRulesCache.from_json(
                    self._meta_file.read_text(encoding="utf-8")
                )
            except Exception:
                self._cache_meta = RemoteRulesCache(url=self._url, ttl=self._ttl)

    def _save_cache_meta(self) -> None:
        self._meta_file.write_text(
            self._cache_meta.to_json(), encoding="utf-8"
        )

    def _fetch_remote(self) -> Optional[str]:
        """从远程 URL 拉取规则内容。"""
        try:
            req = urllib.request.Request(self._url)
            if self._cache_meta.etag:
                req.add_header("If-None-Match", self._cache_meta.etag)
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.status == 304:
                    self._cache_meta.fetched_at = time.time()
                    self._save_cache_meta()
                    return None
                content = resp.read().decode("utf-8")
                etag = resp.headers.get("ETag", "")
                return content
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return None
            raise
        except Exception:
            raise

    @property
    def is_cache_fresh(self) -> bool:
        """缓存是否有效（存在且未过期）。"""
        if not self._cache_file.exists():
            return False
        return not self._cache_meta.is_expired

    @property
    def cache_version(self) -> str:
        return self._cache_meta.version

    def sync(self, force: bool = False) -> bool:
        """同步远端规则到本地缓存。

        Args:
            force: 是否强制刷新，忽略 TTL

        Returns:
            True 表示有更新，False 表示无更新
        """
        if not force and self.is_cache_fresh:
            return False

        try:
            content = self._fetch_remote()
            if content is None:
                return False
            checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if checksum == self._cache_meta.checksum_sha256 and self._cache_file.exists():
                self._cache_meta.fetched_at = time.time()
                self._save_cache_meta()
                return False

            self._cache_file.write_text(content, encoding="utf-8")

            self._cache_meta.fetched_at = time.time()
            self._cache_meta.checksum_sha256 = checksum

            try:
                data = json.loads(content)
                rules = data.get("rules", [])
                self._cache_meta.rules_count = len(rules)
                self._cache_meta.version = data.get("version", "")
            except json.JSONDecodeError:
                self._cache_meta.rules_count = 0

            self._save_cache_meta()
            return True
        except Exception:
            if self._cache_file.exists():
                return False
            raise

    def get_cached_patterns(self) -> List[dict]:
        """从缓存加载规则数据（原始字典格式）。"""
        if not self._cache_file.exists():
            return []
        try:
            content = self._cache_file.read_text(encoding="utf-8")
            data = json.loads(content)
            rules = data.get("rules", [])
            if not isinstance(rules, list):
                return []
            return rules
        except (json.JSONDecodeError, IOError):
            return []

    def clear_cache(self) -> None:
        """清空本地缓存。"""
        if self._cache_file.exists():
            self._cache_file.unlink()
        if self._meta_file.exists():
            self._meta_file.unlink()
        self._cache_meta = RemoteRulesCache(url=self._url, ttl=self._ttl)

    @property
    def cache_info(self) -> dict:
        return {
            "url": self._cache_meta.url,
            "version": self._cache_meta.version,
            "fetched_at": self._cache_meta.fetched_at,
            "ttl": self._cache_meta.ttl,
            "expired": self._cache_meta.is_expired,
            "rules_count": self._cache_meta.rules_count,
            "cache_file": str(self._cache_file),
        }


def fetch_rules_from_url(
    url: str,
    cache_dir: Optional[Path] = None,
    ttl: int = 3600,
    force: bool = False,
) -> Tuple[List[dict], dict]:
    """从 URL 拉取规则并返回（带缓存的便捷函数）。

    Returns:
        (规则列表, 缓存信息字典)
    """
    syncer = RemoteRulesSyncer(url=url, cache_dir=cache_dir, ttl=ttl)
    try:
        syncer.sync(force=force)
    except Exception:
        pass
    patterns = syncer.get_cached_patterns()
    return patterns, syncer.cache_info
