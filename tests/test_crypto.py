"""加密落盘模块单元测试。"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from log_redaction.crypto import (
    EncryptionConfig,
    FileEncryptor,
    decrypt_json_log,
    encrypt_json_log,
    is_encrypted_file,
)


class TestEncryptionConfig:
    def test_default_salt_generated(self):
        config = EncryptionConfig(password="mypassword")
        assert config.salt is not None
        assert len(config.salt) == 16
        assert config.iterations == 200_000

    def test_custom_salt(self):
        salt = b"mysalt1234567890"
        config = EncryptionConfig(password="mypassword", salt=salt)
        assert config.salt == salt


class TestFileEncryptor:
    def test_encrypt_decrypt_bytes(self):
        config = EncryptionConfig(password="test123")
        encryptor = FileEncryptor(config)
        plaintext = b"hello world sensitive data: 13812345678"
        ciphertext = encryptor.encrypt_bytes(plaintext)
        assert ciphertext != plaintext
        decrypted = encryptor.decrypt_bytes(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_text(self):
        config = EncryptionConfig(password="test123")
        encryptor = FileEncryptor(config)
        plaintext = "这是中文敏感信息 手机: 13812345678"
        ciphertext = encryptor.encrypt_text(plaintext)
        decrypted = encryptor.decrypt_text(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_file(self, tmp_path):
        input_file = tmp_path / "input.txt"
        encrypted_file = tmp_path / "encrypted.bin"
        decrypted_file = tmp_path / "decrypted.txt"
        content = b"User login: admin phone: 13812345678 email: test@example.com"
        input_file.write_bytes(content)
        config = EncryptionConfig(password="strongpassword")
        encryptor = FileEncryptor(config)
        encryptor.encrypt_file(input_file, encrypted_file)
        assert encrypted_file.exists()
        assert encrypted_file.read_bytes() != content
        assert is_encrypted_file(encrypted_file)
        encryptor.decrypt_file(encrypted_file, decrypted_file)
        assert decrypted_file.read_bytes() == content

    def test_wrong_password_fails(self, tmp_path):
        input_file = tmp_path / "input.txt"
        encrypted_file = tmp_path / "encrypted.bin"
        input_file.write_text("sensitive data")
        config1 = EncryptionConfig(password="password1")
        encryptor1 = FileEncryptor(config1)
        encryptor1.encrypt_file(input_file, encrypted_file)
        config2 = EncryptionConfig(password="password2")
        encryptor2 = FileEncryptor(config2)
        with pytest.raises(Exception):
            encryptor2.decrypt_file(encrypted_file, tmp_path / "out.txt")

    def test_different_salts_produce_different_ciphertexts(self):
        config1 = EncryptionConfig(password="samepassword", salt=b"salt111111111111")
        config2 = EncryptionConfig(password="samepassword", salt=b"salt222222222222")
        e1 = FileEncryptor(config1)
        e2 = FileEncryptor(config2)
        plaintext = b"same content"
        c1 = e1.encrypt_bytes(plaintext)
        c2 = e2.encrypt_bytes(plaintext)
        assert c1 != c2

    def test_invalid_file_format(self, tmp_path):
        bad_file = tmp_path / "bad.bin"
        bad_file.write_bytes(b"NOTANENCRYPTEDFILELONGENOUGHTOPASS30BYTES")
        config = EncryptionConfig(password="test")
        encryptor = FileEncryptor(config)
        with pytest.raises(ValueError, match="magic 不匹配"):
            encryptor.decrypt_file(bad_file, tmp_path / "out.txt")

    def test_short_file(self, tmp_path):
        short_file = tmp_path / "short.bin"
        short_file.write_bytes(b"abc")
        config = EncryptionConfig(password="test")
        encryptor = FileEncryptor(config)
        with pytest.raises(ValueError, match="文件太短"):
            encryptor.decrypt_file(short_file, tmp_path / "out.txt")

    def test_magic_header(self, tmp_path):
        input_file = tmp_path / "input.txt"
        encrypted_file = tmp_path / "encrypted.bin"
        input_file.write_text("hello")
        config = EncryptionConfig(password="pass")
        encryptor = FileEncryptor(config)
        encryptor.encrypt_file(input_file, encrypted_file)
        with encrypted_file.open("rb") as f:
            magic = f.read(4)
        assert magic == b"LRED"


class TestIsEncryptedFile:
    def test_recognizes_encrypted_file(self, tmp_path):
        f = tmp_path / "encrypted.bin"
        config = EncryptionConfig(password="test")
        encryptor = FileEncryptor(config)
        plain_file = tmp_path / "plain.txt"
        plain_file.write_text("hello")
        encryptor.encrypt_file(plain_file, f)
        assert is_encrypted_file(f) is True

    def test_recognizes_plain_file(self, tmp_path):
        f = tmp_path / "plain.txt"
        f.write_text("hello world")
        assert is_encrypted_file(f) is False

    def test_non_existent_file(self, tmp_path):
        assert is_encrypted_file(tmp_path / "nonexistent") is False


class TestJsonFieldEncryption:
    def test_encrypt_decrypt_json_log_fields(self):
        config = EncryptionConfig(password="testpass")
        encryptor = FileEncryptor(config)
        log_entry = {
            "timestamp": "2026-06-15T10:00:00",
            "level": "INFO",
            "user": "zhangsan",
            "phone": "13812345678",
            "email": "zhangsan@example.com",
        }
        encrypted = encrypt_json_log(log_entry, ["phone", "email"], encryptor)
        assert "phone" not in encrypted
        assert "email" not in encrypted
        assert "phone_enc" in encrypted
        assert "email_enc" in encrypted
        assert encrypted["timestamp"] == "2026-06-15T10:00:00"
        assert encrypted["level"] == "INFO"
        assert encrypted["user"] == "zhangsan"
        decrypted = decrypt_json_log(encrypted, encryptor)
        assert decrypted["phone"] == "13812345678"
        assert decrypted["email"] == "zhangsan@example.com"
        assert decrypted["timestamp"] == "2026-06-15T10:00:00"

    def test_encrypt_field_not_present(self):
        config = EncryptionConfig(password="test")
        encryptor = FileEncryptor(config)
        log_entry = {"message": "hello"}
        result = encrypt_json_log(log_entry, ["phone"], encryptor)
        assert "phone" not in result
        assert "phone_enc" not in result
        assert result["message"] == "hello"

    def test_decrypt_field_that_is_not_encrypted(self):
        config = EncryptionConfig(password="test")
        encryptor = FileEncryptor(config)
        log_entry = {"message": "hello", "phone_enc": "notbase64!!!"}
        result = decrypt_json_log(log_entry, encryptor)
        assert "phone_enc" in result
        assert "phone" not in result
