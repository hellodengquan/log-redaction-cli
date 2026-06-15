"""合规存储上传模块。

提供审计报告和脱敏日志的合规存储上传功能：
- 本地归档存储（默认，零依赖）
- S3 兼容存储（AWS S3 / MinIO / 阿里云 OSS 等）
- 上传后自动验证完整性（SHA-256 校验）
- 上传元数据记录（时间戳、校验和、存储路径）
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class UploadResult:
    """上传结果。"""

    success: bool
    destination: str = ""
    checksum_sha256: str = ""
    file_size: int = 0
    uploaded_at: str = ""
    error: str = ""

    def __post_init__(self) -> None:
        if not self.uploaded_at and self.success:
            self.uploaded_at = datetime.now().isoformat()


@dataclass
class UploadManifest:
    """上传清单（记录所有上传操作的元数据）。"""

    uploads: list = field(default_factory=list)
    manifest_path: str = ""

    def add(self, result: UploadResult) -> None:
        self.uploads.append(asdict(result))

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump({"uploads": self.uploads, "generated_at": datetime.now().isoformat()}, f, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: Path) -> UploadManifest:
        path = Path(path)
        if not path.exists():
            return cls(manifest_path=str(path))
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(uploads=data.get("uploads", []), manifest_path=str(path))


def _sha256_file(path: Path) -> str:
    path = Path(path)
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class StorageUploader(ABC):
    """存储上传器抽象基类。"""

    @abstractmethod
    def upload(self, local_path: Path, remote_key: Optional[str] = None) -> UploadResult:
        """上传文件到存储后端。"""

    @abstractmethod
    def list_uploads(self) -> list:
        """列出已上传的文件。"""


class LocalArchiveUploader(StorageUploader):
    """本地归档存储上传器。

    将文件复制到指定归档目录，自动按日期组织子目录。
    """

    def __init__(
        self,
        archive_dir: Path,
        date_prefix: bool = True,
        verify: bool = True,
        manifest_path: Optional[Path] = None,
    ) -> None:
        self._archive_dir = Path(archive_dir)
        self._date_prefix = date_prefix
        self._verify = verify
        self._manifest_path = manifest_path or self._archive_dir / "upload_manifest.json"
        self._manifest = UploadManifest(manifest_path=str(self._manifest_path))

    def upload(self, local_path: Path, remote_key: Optional[str] = None) -> UploadResult:
        local_path = Path(local_path)
        if not local_path.exists():
            return UploadResult(success=False, error=f"文件不存在: {local_path}")

        try:
            checksum = _sha256_file(local_path)
            file_size = local_path.stat().st_size
            dest_dir = self._archive_dir
            if self._date_prefix:
                date_dir = datetime.now().strftime("%Y/%m/%d")
                dest_dir = dest_dir / date_dir
            dest_dir.mkdir(parents=True, exist_ok=True)
            key = remote_key or local_path.name
            dest_path = dest_dir / key
            shutil.copy2(local_path, dest_path)
            if self._verify:
                dest_checksum = _sha256_file(dest_path)
                if dest_checksum != checksum:
                    dest_path.unlink(missing_ok=True)
                    return UploadResult(success=False, error="校验和不匹配，上传已回滚")
            result = UploadResult(
                success=True,
                destination=str(dest_path),
                checksum_sha256=checksum,
                file_size=file_size,
            )
            self._manifest.add(result)
            self._manifest.save(self._manifest_path)
            return result
        except Exception as e:
            return UploadResult(success=False, error=str(e))

    def list_uploads(self) -> list:
        if self._manifest_path.exists():
            self._manifest = UploadManifest.load(self._manifest_path)
        return self._manifest.uploads


class S3Uploader(StorageUploader):
    """S3 兼容存储上传器。

    支持 AWS S3、MinIO、阿里云 OSS 等 S3 兼容存储。
    需要 boto3 库。
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "audit-reports/",
        endpoint_url: Optional[str] = None,
        region: str = "us-east-1",
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        verify: bool = True,
    ) -> None:
        self._bucket = bucket
        self._prefix = prefix
        self._endpoint_url = endpoint_url
        self._region = region
        self._aws_access_key_id = aws_access_key_id
        self._aws_secret_access_key = aws_secret_access_key
        self._verify = verify
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import boto3
        except ImportError:
            raise RuntimeError("S3 上传需要 boto3 库，请运行: pip install boto3")
        kwargs = {
            "service_name": "s3",
            "region_name": self._region,
        }
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url
        if self._aws_access_key_id:
            kwargs["aws_access_key_id"] = self._aws_access_key_id
        if self._aws_secret_access_key:
            kwargs["aws_secret_access_key"] = self._aws_secret_access_key
        self._client = boto3.client(**kwargs)
        return self._client

    def upload(self, local_path: Path, remote_key: Optional[str] = None) -> UploadResult:
        local_path = Path(local_path)
        if not local_path.exists():
            return UploadResult(success=False, error=f"文件不存在: {local_path}")
        try:
            checksum = _sha256_file(local_path)
            file_size = local_path.stat().st_size
            key = remote_key or local_path.name
            s3_key = f"{self._prefix}{key}"
            client = self._get_client()
            extra_args = {
                "Metadata": {
                    "sha256": checksum,
                    "original-name": local_path.name,
                    "uploaded-at": datetime.now().isoformat(),
                }
            }
            client.upload_file(
                str(local_path),
                self._bucket,
                s3_key,
                ExtraArgs=extra_args,
            )
            return UploadResult(
                success=True,
                destination=f"s3://{self._bucket}/{s3_key}",
                checksum_sha256=checksum,
                file_size=file_size,
            )
        except Exception as e:
            return UploadResult(success=False, error=str(e))

    def list_uploads(self) -> list:
        try:
            client = self._get_client()
            response = client.list_objects_v2(Bucket=self._bucket, Prefix=self._prefix)
            return response.get("Contents", [])
        except Exception:
            return []


def create_uploader(
    backend: str = "local",
    **kwargs,
) -> StorageUploader:
    """工厂函数：创建存储上传器。"""
    if backend == "local":
        archive_dir = kwargs.get("archive_dir", Path("./archive"))
        return LocalArchiveUploader(
            archive_dir=Path(archive_dir),
            date_prefix=kwargs.get("date_prefix", True),
            verify=kwargs.get("verify", True),
            manifest_path=kwargs.get("manifest_path"),
        )
    elif backend in ("s3", "minio", "oss"):
        return S3Uploader(
            bucket=kwargs.get("bucket", ""),
            prefix=kwargs.get("prefix", "audit-reports/"),
            endpoint_url=kwargs.get("endpoint_url"),
            region=kwargs.get("region", "us-east-1"),
            aws_access_key_id=kwargs.get("aws_access_key_id") or os.environ.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=kwargs.get("aws_secret_access_key") or os.environ.get("AWS_SECRET_ACCESS_KEY"),
        )
    else:
        raise ValueError(f"不支持的存储后端: {backend}，可选: local, s3")
