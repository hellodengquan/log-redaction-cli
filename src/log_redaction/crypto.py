"""加密落盘模块。

提供脱敏日志和审计报告的加密存储功能：
- AES-GCM 认证加密（带完整性校验）
- PBKDF2HMAC 密钥派生（基于密码）
- 支持加密整个文件或仅加密敏感字段
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


DEFAULT_ITERATIONS = 200_000
SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32  # AES-256
ENCODING = "utf-8"


@dataclass
class EncryptionConfig:
    """加密配置。"""

    password: str
    salt: Optional[bytes] = None
    iterations: int = DEFAULT_ITERATIONS
    key_length: int = KEY_LENGTH

    def __post_init__(self) -> None:
        if self.salt is None:
            self.salt = secrets.token_bytes(SALT_LENGTH)


class FileEncryptor:
    """文件加密器。

    文件格式（二进制）：
    [magic: 4 bytes] "LRED"
    [version: 2 bytes] 0x0001
    [salt_len: 1 byte]
    [salt: salt_len bytes]
    [iterations: 4 bytes, big-endian]
    [nonce_len: 1 byte]
    [nonce: nonce_len bytes]
    [tag: 16 bytes] (AES-GCM auth tag)
    [ciphertext: rest of file]
    """

    MAGIC = b"LRED"
    VERSION = (0).to_bytes(2, byteorder="big")

    def __init__(self, config: EncryptionConfig) -> None:
        self._config = config

    def _derive_key(self, salt: bytes, iterations: int) -> bytes:
        """从密码派生加密密钥。"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self._config.key_length,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(self._config.password.encode(ENCODING))

    def encrypt_bytes(self, plaintext: bytes) -> bytes:
        """加密字节数据，返回完整的加密文件字节。"""
        salt = self._config.salt if self._config.salt else secrets.token_bytes(SALT_LENGTH)
        iterations = self._config.iterations
        key = self._derive_key(salt, iterations)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(NONCE_LENGTH)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        tag = ciphertext_with_tag[-16:]
        ciphertext = ciphertext_with_tag[:-16]

        parts: List[bytes] = []
        parts.append(self.MAGIC)
        parts.append(self.VERSION)
        parts.append(len(salt).to_bytes(1, byteorder="big"))
        parts.append(salt)
        parts.append(iterations.to_bytes(4, byteorder="big"))
        parts.append(len(nonce).to_bytes(1, byteorder="big"))
        parts.append(nonce)
        parts.append(tag)
        parts.append(ciphertext)
        return b"".join(parts)

    def decrypt_bytes(self, data: bytes) -> bytes:
        """解密加密文件字节，返回原始明文。"""
        if len(data) < 30:
            raise ValueError("加密文件格式无效：文件太短")
        offset = 0
        if data[offset:offset+4] != self.MAGIC:
            raise ValueError("加密文件格式无效：magic 不匹配")
        offset += 4
        offset += 2
        salt_len = data[offset]
        offset += 1
        salt = data[offset:offset+salt_len]
        offset += salt_len
        iterations = int.from_bytes(data[offset:offset+4], byteorder="big")
        offset += 4
        nonce_len = data[offset]
        offset += 1
        nonce = data[offset:offset+nonce_len]
        offset += nonce_len
        tag = data[offset:offset+16]
        offset += 16
        ciphertext = data[offset:]

        key = self._derive_key(salt, iterations)
        aesgcm = AESGCM(key)
        ciphertext_with_tag = ciphertext + tag
        return aesgcm.decrypt(nonce, ciphertext_with_tag, None)

    def encrypt_file(self, plaintext_path: Path, output_path: Path) -> None:
        """加密文件。"""
        plaintext_path = Path(plaintext_path)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = plaintext_path.read_bytes()
        encrypted = self.encrypt_bytes(plaintext)
        output_path.write_bytes(encrypted)

    def decrypt_file(self, encrypted_path: Path, output_path: Path) -> None:
        """解密文件。"""
        encrypted_path = Path(encrypted_path)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        encrypted = encrypted_path.read_bytes()
        plaintext = self.decrypt_bytes(encrypted)
        output_path.write_bytes(plaintext)

    def encrypt_text(self, text: str) -> bytes:
        """加密字符串。"""
        return self.encrypt_bytes(text.encode(ENCODING))

    def decrypt_text(self, data: bytes) -> str:
        """解密为字符串。"""
        return self.decrypt_bytes(data).decode(ENCODING)


def is_encrypted_file(path: Path) -> bool:
    """检查文件是否为 LRED 加密格式。"""
    path = Path(path)
    if not path.exists() or path.stat().st_size < 4:
        return False
    with path.open("rb") as f:
        magic = f.read(4)
    return magic == FileEncryptor.MAGIC


def encrypt_json_log(
    log_entry: dict,
    sensitive_fields: List[str],
    encryptor: FileEncryptor,
) -> dict:
    """加密 JSON 日志中指定的敏感字段。

    加密后的字段名后缀 `_enc`，值为 base64 编码的密文。
    """
    result = dict(log_entry)
    for field in sensitive_fields:
        if field in result and result[field] is not None:
            value = str(result[field])
            ciphertext = encryptor.encrypt_text(value)
            result[f"{field}_enc"] = base64.b64encode(ciphertext).decode("ascii")
            del result[field]
    return result


def decrypt_json_log(
    log_entry: dict,
    encryptor: FileEncryptor,
) -> dict:
    """解密 JSON 日志中 `_enc` 后缀的敏感字段。"""
    result = dict(log_entry)
    keys = list(result.keys())
    for key in keys:
        if key.endswith("_enc"):
            original_key = key[:-4]
            try:
                ciphertext = base64.b64decode(result[key])
                plaintext = encryptor.decrypt_text(ciphertext)
                result[original_key] = plaintext
                del result[key]
            except (ValueError, base64.binascii.Error):
                pass
    return result
