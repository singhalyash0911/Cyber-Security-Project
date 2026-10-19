"""
SecureStego — Encryption Module
================================
Implements authenticated symmetric encryption using AES-256-GCM and
password-based key derivation using PBKDF2-HMAC-SHA256.

Designed for MCA 3rd-Semester Cyber Security Academic Project.
Student Responsibility: Student 1 (Backend & Security Architecture)
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# --- Configuration Constants ---
# PBKDF2 parameters:
# 100,000 iterations of SHA-256 is an OWASP-recommended baseline for PBKDF2.
# It balances cryptographic resistance against brute-force attacks with
# fast responsiveness in a local web application.
PBKDF2_ITERATIONS = 100_000
KEY_LENGTH_BYTES = 32     # 256 bits for AES-256
SALT_LENGTH_BYTES = 16    # 128-bit random salt
NONCE_LENGTH_BYTES = 12   # 96-bit random nonce standard for AES-GCM
TAG_LENGTH_BYTES = 16     # 128-bit authentication tag appended by AESGCM

# Minimum valid package size: salt (16) + nonce (12) + tag (16) = 44 bytes
MIN_PACKAGE_SIZE = SALT_LENGTH_BYTES + NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES


class EncryptionError(Exception):
    """Base exception class for encryption and decryption errors."""
    pass


class DecryptionError(EncryptionError):
    """Raised when decryption or authentication fails (wrong password or tampered data)."""
    pass


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit symmetric encryption key from a user password and salt
    using PBKDF2 (Password-Based Key Derivation Function 2) with HMAC-SHA256.

    Parameters:
        password (str): The secret password entered by the user.
        salt (bytes): 16 cryptographically random bytes.

    Returns:
        bytes: 32-byte (256-bit) symmetric key.
    """
    if not isinstance(password, str) or not password:
        raise EncryptionError("A valid, non-empty password is required.")
    if not isinstance(salt, bytes) or len(salt) != SALT_LENGTH_BYTES:
        raise EncryptionError(f"Salt must be exactly {SALT_LENGTH_BYTES} bytes.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(plaintext: str, password: str) -> bytes:
    """
    Encrypts a plaintext message using AES-256-GCM with a key derived from password.

    Workflow:
    1. Validate non-empty plaintext and password.
    2. Generate a fresh 16-byte random salt.
    3. Derive a 256-bit key from password + salt via PBKDF2-HMAC-SHA256.
    4. Generate a fresh 12-byte random nonce (initialization vector).
    5. Encrypt the plaintext bytes with AES-256-GCM (produces ciphertext + 16-byte auth tag).
    6. Pack and return: salt (16 bytes) + nonce (12 bytes) + ciphertext_with_tag.

    Parameters:
        plaintext (str): Secret message to encrypt.
        password (str): Secret passphrase for key derivation.

    Returns:
        bytes: The combined binary encrypted package.
    """
    if not isinstance(plaintext, str) or len(plaintext.strip()) == 0:
        raise EncryptionError("Secret message cannot be empty.")
    if not isinstance(password, str) or len(password) == 0:
        raise EncryptionError("Password cannot be empty.")

    # Convert message to UTF-8 bytes
    plaintext_bytes = plaintext.encode("utf-8")

    # Step 1: Generate fresh cryptographically secure random salt
    salt = os.urandom(SALT_LENGTH_BYTES)

    # Step 2: Derive AES key using PBKDF2
    key = derive_key(password, salt)

    # Step 3: Generate fresh cryptographically secure random nonce
    nonce = os.urandom(NONCE_LENGTH_BYTES)

    # Step 4: Encrypt using AES-256 in Galois/Counter Mode (GCM)
    # Note: AESGCM automatically appends the 16-byte authentication tag to the ciphertext.
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)

    # Step 5: Assemble the package: [SALT 16B] + [NONCE 12B] + [CIPHERTEXT + TAG]
    encrypted_package = salt + nonce + ciphertext_and_tag
    return encrypted_package


def decrypt_message(encrypted_package: bytes, password: str) -> str:
    """
    Decrypts an encrypted package using AES-256-GCM and verifies authenticity.

    Workflow:
    1. Validate minimum package size (at least 44 bytes).
    2. Extract salt (first 16 bytes).
    3. Extract nonce (next 12 bytes).
    4. Extract ciphertext and authentication tag (remaining bytes).
    5. Derive the 256-bit key from password + salt via PBKDF2.
    6. Authenticate and decrypt with AES-256-GCM.
    7. Return decrypted plaintext string.

    Parameters:
        encrypted_package (bytes): The binary package containing salt, nonce, and ciphertext.
        password (str): Secret passphrase supplied by user.

    Returns:
        str: Recovered original plaintext message.

    Raises:
        DecryptionError: If the password is wrong, or if data was tampered with.
    """
    if not isinstance(encrypted_package, (bytes, bytearray)):
        raise DecryptionError("Invalid payload data type.")
    if len(encrypted_package) < MIN_PACKAGE_SIZE:
        raise DecryptionError("Corrupted or incomplete encrypted payload.")
    if not isinstance(password, str) or len(password) == 0:
        raise DecryptionError("Please provide a password to decrypt the message.")

    # Slice components from the binary package
    salt = encrypted_package[:SALT_LENGTH_BYTES]
    nonce_start = SALT_LENGTH_BYTES
    nonce_end = nonce_start + NONCE_LENGTH_BYTES
    nonce = encrypted_package[nonce_start:nonce_end]
    ciphertext_and_tag = encrypted_package[nonce_end:]

    # Derive key from provided password and extracted salt
    key = derive_key(password, salt)

    # Attempt AES-GCM authenticated decryption
    try:
        aesgcm = AESGCM(key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data=None)
        return plaintext_bytes.decode("utf-8")
    except InvalidTag:
        # InvalidTag means either the password is wrong or the ciphertext was altered!
        raise DecryptionError(
            "Authentication failed: Incorrect password or corrupted payload."
        )
    except UnicodeDecodeError:
        raise DecryptionError(
            "Decrypted data could not be decoded as UTF-8 text."
        )
    except Exception as e:
        # Avoid leaking internal stack trace details in user-facing message
        raise DecryptionError(
            "Authentication failed: Incorrect password or corrupted payload."
        )
