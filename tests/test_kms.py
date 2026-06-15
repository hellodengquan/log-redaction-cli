"""KMS 密钥管理单元测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from log_redaction.kms import (
    KmsEncryptor,
    KeyMetadata,
    KeyVersion,
    LocalKeyProvider,
    create_key_provider,
    is_kms_encrypted,
)


class TestKeyMetadata:
    def test_create_and_save(self, tmp_path):
        meta = KeyMetadata(key_id="test-key", rotation_days=30)
        meta.versions.append(KeyVersion(version_id="v1", created_at="2026-01-01", active=True))
        path = tmp_path / "meta.json"
        meta.to_json(path)
        assert path.exists()
        loaded = KeyMetadata.from_json(path)
        assert loaded.key_id == "test-key"
        assert loaded.rotation_days == 30
        assert len(loaded.versions) == 1
        assert loaded.versions[0].version_id == "v1"

    def test_active_version(self):
        meta = KeyMetadata(key_id="k")
        meta.versions = [
            KeyVersion(version_id="v1", created_at="2026-01-01", active=False),
            KeyVersion(version_id="v2", created_at="2026-02-01", active=True),
        ]
        assert meta.active_version.version_id == "v2"

    def test_no_active_version(self):
        meta = KeyMetadata(key_id="k")
        assert meta.active_version is None


class TestLocalKeyProvider:
    def test_get_current_key(self, tmp_path):
        provider = LocalKeyProvider(
            password="test-password",
            key_dir=tmp_path / "keys",
            key_id="test",
        )
        key, version_id = provider.get_current_key()
        assert len(key) == 32
        assert version_id.startswith("v")

    def test_rotate_creates_new_version(self, tmp_path):
        provider = LocalKeyProvider(
            password="test-password",
            key_dir=tmp_path / "keys",
            key_id="test",
        )
        _, v1 = provider.get_current_key()
        new_v = provider.rotate()
        assert new_v != v1
        _, v2 = provider.get_current_key()
        assert v2 == new_v

    def test_decrypt_with_old_version(self, tmp_path):
        provider = LocalKeyProvider(
            password="test-password",
            key_dir=tmp_path / "keys",
            key_id="test",
        )
        encryptor = KmsEncryptor(provider)
        plaintext = b"sensitive data: 13812345678"
        ciphertext = encryptor.encrypt_bytes(plaintext)
        provider.rotate()
        decrypted = encryptor.decrypt_bytes(ciphertext)
        assert decrypted == plaintext

    def test_metadata_persisted(self, tmp_path):
        key_dir = tmp_path / "keys"
        provider1 = LocalKeyProvider(
            password="test-password",
            key_dir=key_dir,
            key_id="persist",
        )
        v1 = provider1.get_current_key()[1]
        provider1.rotate()
        v2 = provider1.get_current_key()[1]
        provider2 = LocalKeyProvider(
            password="test-password",
            key_dir=key_dir,
            key_id="persist",
        )
        active = provider2.get_current_key()[1]
        assert active == v2


class TestKmsEncryptor:
    def test_encrypt_decrypt_bytes(self, tmp_path):
        provider = LocalKeyProvider(
            password="test-password",
            key_dir=tmp_path / "keys",
        )
        encryptor = KmsEncryptor(provider)
        plaintext = b"hello world sensitive: 13812345678"
        ciphertext = encryptor.encrypt_bytes(plaintext)
        assert ciphertext != plaintext
        decrypted = encryptor.decrypt_bytes(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_file(self, tmp_path):
        provider = LocalKeyProvider(
            password="test-password",
            key_dir=tmp_path / "keys",
        )
        encryptor = KmsEncryptor(provider)
        src = tmp_path / "plain.txt"
        src.write_text("sensitive: 13812345678")
        enc = tmp_path / "plain.kms"
        dec = tmp_path / "decrypted.txt"
        encryptor.encrypt_file(src, enc)
        assert enc.exists()
        assert is_kms_encrypted(enc)
        encryptor.decrypt_file(enc, dec)
        assert dec.read_text() == "sensitive: 13812345678"

    def test_invalid_magic(self, tmp_path):
        provider = LocalKeyProvider(
            password="test-password",
            key_dir=tmp_path / "keys",
        )
        encryptor = KmsEncryptor(provider)
        with pytest.raises(ValueError, match="magic 不匹配"):
            encryptor.decrypt_bytes(b"INVALIDDATA" * 10)


class TestCreateKeyProvider:
    def test_local_backend(self, tmp_path):
        provider = create_key_provider(
            backend="local",
            password="mypassword",
            key_dir=tmp_path / "keys",
        )
        assert isinstance(provider, LocalKeyProvider)

    def test_local_requires_password(self, tmp_path):
        with pytest.raises(ValueError, match="password"):
            create_key_provider(backend="local", key_dir=tmp_path / "keys")

    def test_invalid_backend(self):
        with pytest.raises(ValueError, match="不支持的密钥后端"):
            create_key_provider(backend="invalid")
