"""KMS 与 age 密钥轮转模块。

提供密钥管理抽象层，支持：
- 本地密码派生密钥（向后兼容 EncryptionConfig）
- age 加密后端（公钥加密，无需分发密码）
- KMS 密钥轮转（自动生成新版本密钥，旧版本仍可解密）
- 密钥版本追踪与版本化加密文件格式
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


KEY_VERSION_HEADER = b"LKMS"
KEY_VERSION_LENGTH = 4


@dataclass
class KeyVersion:
    """密钥版本记录。"""

    version_id: str
    created_at: str
    algorithm: str = "aes-256-gcm"
    active: bool = True
    key_data_ref: str = ""


@dataclass
class KeyMetadata:
    """密钥元数据（持久化到 JSON 文件）。"""

    key_id: str
    versions: List[KeyVersion] = field(default_factory=list)
    rotation_days: int = 90
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.versions:
            self.versions = []

    @property
    def active_version(self) -> Optional[KeyVersion]:
        for v in reversed(self.versions):
            if v.active:
                return v
        return None

    def to_json(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(asdict(self), f, ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, path: Path) -> KeyMetadata:
        path = Path(path)
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        versions = [KeyVersion(**v) for v in data.get("versions", [])]
        return cls(
            key_id=data["key_id"],
            versions=versions,
            rotation_days=data.get("rotation_days", 90),
            created_at=data.get("created_at", ""),
        )


class KeyProvider(ABC):
    """密钥提供者抽象基类。"""

    @abstractmethod
    def get_current_key(self) -> Tuple[bytes, str]:
        """返回 (密钥字节, 版本ID)，用于加密。"""

    @abstractmethod
    def get_key_by_version(self, version_id: str) -> bytes:
        """根据版本 ID 获取密钥，用于解密。"""

    @abstractmethod
    def rotate(self) -> str:
        """轮转密钥，返回新版本 ID。"""


class LocalKeyProvider(KeyProvider):
    """本地密码派生密钥提供者（向后兼容）。

    使用 PBKDF2-HMAC-SHA256 从密码派生 AES-256 密钥，
    支持版本化密钥轮转。
    """

    def __init__(
        self,
        password: str,
        key_dir: Optional[Path] = None,
        key_id: str = "local-default",
        iterations: int = 200_000,
    ) -> None:
        self._password = password
        self._iterations = iterations
        self._key_id = key_id
        self._key_dir = key_dir or Path(tempfile.gettempdir()) / "log-redaction-keys"
        self._key_dir.mkdir(parents=True, exist_ok=True)
        self._metadata_path = self._key_dir / f"{key_id}.json"
        self._metadata: Optional[KeyMetadata] = None
        self._derived_keys: Dict[str, bytes] = {}
        self._load_or_init()

    def _load_or_init(self) -> None:
        if self._metadata_path.exists():
            self._metadata = KeyMetadata.from_json(self._metadata_path)
        else:
            self._metadata = KeyMetadata(key_id=self._key_id)
            self.rotate()
            self._metadata.to_json(self._metadata_path)

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self._iterations,
        )
        return kdf.derive(self._password.encode("utf-8"))

    def _get_or_derive(self, version_id: str) -> bytes:
        if version_id in self._derived_keys:
            return self._derived_keys[version_id]
        salt_path = self._key_dir / f"{self._key_id}_{version_id}.salt"
        if not salt_path.exists():
            raise KeyError(f"密钥版本 {version_id} 的 salt 文件不存在")
        salt = salt_path.read_bytes()
        key = self._derive_key(salt)
        self._derived_keys[version_id] = key
        return key

    def get_current_key(self) -> Tuple[bytes, str]:
        active = self._metadata.active_version
        if active is None:
            raise RuntimeError("没有可用的活跃密钥版本")
        key = self._get_or_derive(active.version_id)
        return key, active.version_id

    def get_key_by_version(self, version_id: str) -> bytes:
        return self._get_or_derive(version_id)

    def rotate(self) -> str:
        version_id = datetime.now().strftime("v%Y%m%d%H%M%S") + f"_{secrets.token_hex(4)}"
        salt = secrets.token_bytes(16)
        salt_path = self._key_dir / f"{self._key_id}_{version_id}.salt"
        salt_path.write_bytes(salt)
        key = self._derive_key(salt)
        self._derived_keys[version_id] = key
        new_version = KeyVersion(
            version_id=version_id,
            created_at=datetime.now().isoformat(),
            active=True,
        )
        for v in self._metadata.versions:
            v.active = False
        self._metadata.versions.append(new_version)
        self._metadata.to_json(self._metadata_path)
        return version_id


class AgeKeyProvider(KeyProvider):
    """age 加密后端密钥提供者。

    使用 age (https://age-encryption.org) 进行公钥加密。
    - 加密时使用接收者公钥
    - 解密时使用身份私钥
    - 密钥轮转通过添加新公钥实现
    """

    def __init__(
        self,
        recipient_keys: Optional[List[str]] = None,
        identity_file: Optional[Path] = None,
        key_dir: Optional[Path] = None,
        key_id: str = "age-default",
    ) -> None:
        self._recipient_keys = recipient_keys or []
        self._identity_file = identity_file
        self._key_dir = key_dir or Path(tempfile.gettempdir()) / "log-redaction-keys"
        self._key_dir.mkdir(parents=True, exist_ok=True)
        self._key_id = key_id
        self._metadata_path = self._key_dir / f"{key_id}.json"
        self._metadata: Optional[KeyMetadata] = None
        self._age_bin = self._find_age()
        self._load_or_init()

    def _find_age(self) -> str:
        age_path = shutil.which("age")
        if age_path:
            return age_path
        return "age"

    def _load_or_init(self) -> None:
        if self._metadata_path.exists():
            self._metadata = KeyMetadata.from_json(self._metadata_path)
        else:
            self._metadata = KeyMetadata(key_id=self._key_id)
            self._generate_keypair()
            self._metadata.to_json(self._metadata_path)

    def _generate_keypair(self) -> str:
        version_id = datetime.now().strftime("v%Y%m%d%H%M%S") + f"_{secrets.token_hex(4)}"
        identity_path = self._key_dir / f"{self._key_id}_{version_id}.key"
        try:
            result = subprocess.run(
                [self._age_bin, "-o", str(identity_path), "--generate-key"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                raise RuntimeError(f"age 密钥生成失败: {result.stderr}")
            identity_path.chmod(0o600)
            with identity_path.open("r") as f:
                first_line = f.readline().strip()
            public_key = first_line.replace("# public key: ", "") if first_line.startswith("#") else ""
            if not public_key:
                pub_result = subprocess.run(
                    [self._age_bin, "-y", str(identity_path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                public_key = pub_result.stdout.strip()
        except FileNotFoundError:
            version_id = datetime.now().strftime("v%Y%m%d%H%M%S") + f"_{secrets.token_hex(4)}"
            identity_path = self._key_dir / f"{self._key_id}_{version_id}.key"
            identity_path.write_text(f"# age key (fallback - age not found)\n# version: {version_id}\n")
            public_key = ""
        new_version = KeyVersion(
            version_id=version_id,
            created_at=datetime.now().isoformat(),
            algorithm="age-x25519",
            active=True,
            key_data_ref=public_key,
        )
        for v in self._metadata.versions:
            v.active = False
        self._metadata.versions.append(new_version)
        return version_id

    def get_current_key(self) -> Tuple[bytes, str]:
        active = self._metadata.active_version
        if active is None:
            raise RuntimeError("没有可用的活跃密钥版本")
        return active.key_data_ref.encode("utf-8"), active.version_id

    def get_key_by_version(self, version_id: str) -> bytes:
        for v in self._metadata.versions:
            if v.version_id == version_id:
                return v.key_data_ref.encode("utf-8")
        raise KeyError(f"密钥版本 {version_id} 不存在")

    def rotate(self) -> str:
        return self._generate_keypair()

    @property
    def current_recipient(self) -> str:
        active = self._metadata.active_version
        if active and active.key_data_ref:
            return active.key_data_ref
        if self._recipient_keys:
            return self._recipient_keys[0]
        return ""

    @property
    def current_identity_file(self) -> Optional[Path]:
        active = self._metadata.active_version
        if active:
            identity_path = self._key_dir / f"{self._key_id}_{active.version_id}.key"
            if identity_path.exists():
                return identity_path
        return self._identity_file

    def encrypt_data(self, plaintext: bytes) -> bytes:
        recipient = self.current_recipient
        if not recipient or not self._age_bin:
            raise RuntimeError("没有可用的 age 公钥或 age 可执行文件")
        result = subprocess.run(
            [self._age_bin, "-r", recipient],
            input=plaintext,
            capture_output=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"age 加密失败: {result.stderr.decode('utf-8', errors='replace')}")
        return result.stdout

    def decrypt_data(self, ciphertext: bytes) -> bytes:
        identity = self.current_identity_file
        if identity is None or not self._age_bin:
            raise RuntimeError("没有可用的 age 私钥或 age 可执行文件")
        result = subprocess.run(
            [self._age_bin, "-d", "-i", str(identity)],
            input=ciphertext,
            capture_output=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"age 解密失败: {result.stderr.decode('utf-8', errors='replace')}")
        return result.stdout


class KmsEncryptor:
    """KMS 密钥管理加密器。

    统一封装本地密钥和 age 后端，提供版本化加密/解密。
    加密文件格式：
    [magic: 4 bytes] "LKMS"
    [version_len: 2 bytes, big-endian]
    [version_id: version_len bytes]
    [ciphertext: rest of file]
    """

    MAGIC = KEY_VERSION_HEADER

    def __init__(self, provider: KeyProvider) -> None:
        self._provider = provider

    def encrypt_bytes(self, plaintext: bytes) -> bytes:
        if isinstance(self._provider, AgeKeyProvider):
            age_ciphertext = self._provider.encrypt_data(plaintext)
            return age_ciphertext
        key, version_id = self._provider.get_current_key()
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        version_bytes = version_id.encode("utf-8")
        parts = [
            self.MAGIC,
            len(version_bytes).to_bytes(2, byteorder="big"),
            version_bytes,
            len(nonce).to_bytes(1, byteorder="big"),
            nonce,
            ciphertext_with_tag,
        ]
        return b"".join(parts)

    def decrypt_bytes(self, data: bytes) -> bytes:
        if isinstance(self._provider, AgeKeyProvider):
            return self._provider.decrypt_data(data)
        if len(data) < 8:
            raise ValueError("KMS 加密文件格式无效：文件太短")
        offset = 0
        if data[offset:offset+4] != self.MAGIC:
            raise ValueError("KMS 加密文件格式无效：magic 不匹配")
        offset += 4
        version_len = int.from_bytes(data[offset:offset+2], byteorder="big")
        offset += 2
        version_id = data[offset:offset+version_len].decode("utf-8")
        offset += version_len
        nonce_len = data[offset]
        offset += 1
        nonce = data[offset:offset+nonce_len]
        offset += nonce_len
        ciphertext_with_tag = data[offset:]
        key = self._provider.get_key_by_version(version_id)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext_with_tag, None)

    def encrypt_file(self, plaintext_path: Path, output_path: Path) -> None:
        plaintext_path = Path(plaintext_path)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        encrypted = self.encrypt_bytes(plaintext_path.read_bytes())
        output_path.write_bytes(encrypted)

    def decrypt_file(self, encrypted_path: Path, output_path: Path) -> None:
        encrypted_path = Path(encrypted_path)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = self.decrypt_bytes(encrypted_path.read_bytes())
        output_path.write_bytes(plaintext)


def is_kms_encrypted(path: Path) -> bool:
    path = Path(path)
    if not path.exists() or path.stat().st_size < 4:
        return False
    with path.open("rb") as f:
        magic = f.read(4)
    return magic == KEY_VERSION_HEADER


def create_key_provider(
    backend: str = "local",
    password: Optional[str] = None,
    key_dir: Optional[Path] = None,
    key_id: str = "default",
    age_recipients: Optional[List[str]] = None,
    age_identity: Optional[Path] = None,
) -> KeyProvider:
    """工厂函数：创建密钥提供者。"""
    if backend == "local":
        if not password:
            raise ValueError("本地密钥后端需要提供 password")
        return LocalKeyProvider(password=password, key_dir=key_dir, key_id=key_id)
    elif backend == "age":
        return AgeKeyProvider(
            recipient_keys=age_recipients,
            identity_file=age_identity,
            key_dir=key_dir,
            key_id=key_id,
        )
    else:
        raise ValueError(f"不支持的密钥后端: {backend}，可选: local, age")
