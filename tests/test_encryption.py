"""
Tests for SecureStego Encryption Module
========================================
Covers AES-256-GCM authenticated encryption, PBKDF2-HMAC-SHA256 key derivation,
tamper detection, incorrect password rejection, and Unicode support.
"""

import pytest
import os
import sys

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from encryption import (
    encrypt_message,
    decrypt_message,
    derive_key,
    EncryptionError,
    DecryptionError,
    SALT_LENGTH_BYTES,
    NONCE_LENGTH_BYTES,
    KEY_LENGTH_BYTES,
    MIN_PACKAGE_SIZE
)


class TestEncryption:
    """Test suite for AES-256-GCM encryption and decryption."""

    def test_encrypt_decrypt_roundtrip_simple(self):
        """Test standard encryption and successful decryption with matching password."""
        message = "Confidential MCA Project Report - Top Secret"
        password = "MasterPassword#2026!"

        encrypted = encrypt_message(message, password)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) >= MIN_PACKAGE_SIZE

        decrypted = decrypt_message(encrypted, password)
        assert decrypted == message

    def test_incorrect_password_fails(self):
        """Ensure decryption fails cleanly when provided an incorrect password."""
        message = "Secret Cyber Security Mission"
        password = "CorrectPassword123"
        wrong_password = "WrongPassword999"

        encrypted = encrypt_message(message, password)

        with pytest.raises(DecryptionError) as exc_info:
            decrypt_message(encrypted, wrong_password)
        assert "Authentication failed" in str(exc_info.value)

    def test_tampered_ciphertext_fails(self):
        """Ensure bit-level modifications trigger AES-GCM authentication failure."""
        message = "Integrity is paramount in cryptography."
        password = "SecurePassword123"

        encrypted = bytearray(encrypt_message(message, password))

        # Tamper with the last byte (part of AES-GCM authentication tag)
        encrypted[-1] ^= 0x01

        with pytest.raises(DecryptionError) as exc_info:
            decrypt_message(bytes(encrypted), password)
        assert "Authentication failed" in str(exc_info.value)

    def test_tampered_nonce_fails(self):
        """Ensure altering the nonce causes authentication failure."""
        message = "Nonce tamper check."
        password = "Password123"

        encrypted = bytearray(encrypt_message(message, password))
        # Nonce is located at bytes 16 to 28
        encrypted[SALT_LENGTH_BYTES + 2] ^= 0xAA

        with pytest.raises(DecryptionError):
            decrypt_message(bytes(encrypted), password)

    def test_unicode_and_special_characters(self):
        """Test encryption and decryption of multilingual text, symbols, and emojis."""
        message = (
            "CyberSec 2026: 🔒 🛡️ 🔑 — こんにちは世界 | "
            r"Special chars: !@#$%^&*()_+{}[]|\:;\"'<>,.?/~`" + "\n"
            "Multi-line secret message with tabs\tand newlines."
        )
        password = "P@sswørd_With_Üñîcødë!_2026"

        encrypted = encrypt_message(message, password)
        decrypted = decrypt_message(encrypted, password)
        assert decrypted == message

    def test_fresh_salt_and_nonce_uniqueness(self):
        """Verify that encrypting the same text twice generates completely different ciphertexts."""
        message = "Identical message test"
        password = "SamePassword123"

        enc1 = encrypt_message(message, password)
        enc2 = encrypt_message(message, password)

        assert enc1 != enc2
        # Salt (first 16 bytes) and Nonce (next 12 bytes) must be distinct
        assert enc1[:SALT_LENGTH_BYTES] != enc2[:SALT_LENGTH_BYTES]
        assert enc1[SALT_LENGTH_BYTES:SALT_LENGTH_BYTES + NONCE_LENGTH_BYTES] != \
               enc2[SALT_LENGTH_BYTES:SALT_LENGTH_BYTES + NONCE_LENGTH_BYTES]

        # Both must still decrypt to the original message
        assert decrypt_message(enc1, password) == message
        assert decrypt_message(enc2, password) == message

    def test_empty_message_rejected(self):
        """Ensure empty or whitespace-only messages are rejected."""
        with pytest.raises(EncryptionError):
            encrypt_message("", "password123")
        with pytest.raises(EncryptionError):
            encrypt_message("   \n\t  ", "password123")

    def test_empty_password_rejected(self):
        """Ensure empty password raises an error during encryption and decryption."""
        with pytest.raises(EncryptionError):
            encrypt_message("Some secret", "")

        with pytest.raises(DecryptionError):
            decrypt_message(b"dummy_payload_bytes_at_least_44_bytes_long_12345678901234567890", "")

    def test_truncated_payload_rejected(self):
        """Ensure short or malformed payloads are rejected immediately."""
        with pytest.raises(DecryptionError):
            decrypt_message(b"too_short", "password123")

    def test_key_derivation_consistency(self):
        """Ensure PBKDF2 derives the same key for identical password and salt."""
        salt = os.urandom(SALT_LENGTH_BYTES)
        key1 = derive_key("MyPassword", salt)
        key2 = derive_key("MyPassword", salt)

        assert key1 == key2
        assert len(key1) == KEY_LENGTH_BYTES
