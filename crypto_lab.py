"""
SecureStego — Crypto Lab Educational Module
============================================
Educational cryptographic primitives for MCA Cyber Security syllabus demonstration:
1. AES-256-GCM (reusing encryption.py)
2. Caesar Cipher (classical substitution cipher)
3. RSA-2048 with OAEP-SHA256 (asymmetric encryption demonstration)
4. SHA-256 (cryptographic hash function & avalanche effect)

Designed for academic demonstration. Caesar cipher is strictly for education.
"""

import base64
import hashlib
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

from encryption import (
    derive_key,
    encrypt_message,
    decrypt_message,
    SALT_LENGTH_BYTES,
    NONCE_LENGTH_BYTES,
    KEY_LENGTH_BYTES,
    TAG_LENGTH_BYTES,
    MIN_PACKAGE_SIZE,
    EncryptionError,
    DecryptionError,
)


class CryptoLabError(Exception):
    """Base exception class for Crypto Lab errors."""
    pass


# ==============================================================================
# 1. AES-256-GCM Demonstration (Reusing encryption.py)
# ==============================================================================

def aes_demo_encrypt(plaintext: str, password: str) -> Dict[str, Any]:
    """
    Encrypts plaintext with AES-256-GCM using the project's core encryption module
    and extracts internal components (salt, nonce, derived key, ciphertext, auth tag)
    for educational breakdown.
    """
    if not isinstance(plaintext, str) or not plaintext.strip():
        raise CryptoLabError("Plaintext message cannot be empty.")
    if not isinstance(password, str) or not password:
        raise CryptoLabError("Password cannot be empty.")

    # Call project's core encryption function
    package = encrypt_message(plaintext, password)

    # Slice components from package: [Salt 16B] [Nonce 12B] [Ciphertext N] [Tag 16B]
    salt = package[:SALT_LENGTH_BYTES]
    nonce = package[SALT_LENGTH_BYTES:SALT_LENGTH_BYTES + NONCE_LENGTH_BYTES]
    ciphertext_and_tag = package[SALT_LENGTH_BYTES + NONCE_LENGTH_BYTES:]
    ciphertext = ciphertext_and_tag[:-TAG_LENGTH_BYTES]
    tag = ciphertext_and_tag[-TAG_LENGTH_BYTES:]

    # Derive the 256-bit key to show what PBKDF2 computed
    derived_key = derive_key(password, salt)

    return {
        "plaintext": plaintext,
        "password_masked": "•" * len(password),
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "derived_key_hex": derived_key.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "tag_hex": tag.hex(),
        "package_base64": base64.b64encode(package).decode("utf-8"),
        "package_hex": package.hex(),
        "key_bits": KEY_LENGTH_BYTES * 8,
        "salt_bytes": len(salt),
        "nonce_bytes": len(nonce),
        "ciphertext_bytes": len(ciphertext),
        "tag_bytes": len(tag),
        "total_package_bytes": len(package),
    }


def aes_demo_decrypt(package_input: str, password: str) -> Dict[str, Any]:
    """
    Decrypts an AES-256-GCM package string (hex or base64) and verifies authenticity.
    """
    if not isinstance(package_input, str) or not package_input.strip():
        raise CryptoLabError("Encrypted package cannot be empty.")
    if not isinstance(password, str) or not password:
        raise CryptoLabError("Password cannot be empty.")

    clean_str = package_input.strip()

    # Try decoding as Base64 first, then Hex
    raw_bytes = None
    try:
        raw_bytes = base64.b64decode(clean_str, validate=True)
    except Exception:
        try:
            raw_bytes = bytes.fromhex(clean_str)
        except Exception:
            raise CryptoLabError("Package must be a valid Base64 or Hex-encoded string.")

    if len(raw_bytes) < MIN_PACKAGE_SIZE:
        raise CryptoLabError(f"Package is too short. Minimum size is {MIN_PACKAGE_SIZE} bytes.")

    try:
        plaintext = decrypt_message(raw_bytes, password)
        return {
            "success": True,
            "decrypted_plaintext": plaintext,
            "verified": True,
            "message": "Authentication tag verified successfully. Plaintext recovered."
        }
    except DecryptionError as de:
        raise CryptoLabError(str(de))
    except Exception as e:
        raise CryptoLabError(f"Decryption failed: {str(e)}")


# ==============================================================================
# 2. Caesar Cipher Demonstration (Substitution Cipher)
# ==============================================================================

def caesar_encrypt(plaintext: str, shift: int) -> str:
    """
    Encrypts text using classical Caesar substitution cipher.
    Preserves uppercase, lowercase, and leaves non-alphabetic characters untouched.
    """
    if not isinstance(plaintext, str):
        raise CryptoLabError("Plaintext must be a string.")
    if not isinstance(shift, int):
        try:
            shift = int(shift)
        except (ValueError, TypeError):
            raise CryptoLabError("Shift value must be an integer.")

    shift = shift % 26
    result = []
    for char in plaintext:
        if 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        elif 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        else:
            result.append(char)
    return "".join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """
    Decrypts text encrypted with classical Caesar substitution cipher.
    """
    if not isinstance(shift, int):
        try:
            shift = int(shift)
        except (ValueError, TypeError):
            raise CryptoLabError("Shift value must be an integer.")
    return caesar_encrypt(ciphertext, -shift)


def caesar_demo(text: str, shift: int, mode: str = "encrypt") -> Dict[str, Any]:
    """
    Full Caesar cipher demonstration returning mapped alphabets and processed text.
    """
    if not text:
        raise CryptoLabError("Input text cannot be empty.")
    try:
        shift_int = int(shift)
    except (ValueError, TypeError):
        raise CryptoLabError("Shift must be an integer between 1 and 25.")

    normalized_shift = shift_int % 26

    # Generate substitution mapping table for display
    plain_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    shifted_alpha = "".join(chr((i + normalized_shift) % 26 + ord('A')) for i in range(26))

    if mode == "decrypt":
        output_text = caesar_decrypt(text, shift_int)
    else:
        output_text = caesar_encrypt(text, shift_int)

    return {
        "input_text": text,
        "output_text": output_text,
        "shift": shift_int,
        "normalized_shift": normalized_shift,
        "mode": mode,
        "plain_alphabet": plain_alpha,
        "shifted_alphabet": shifted_alpha,
    }


# ==============================================================================
# 3. RSA Public/Private Key Demonstration (Asymmetric Encryption)
# ==============================================================================

def generate_demo_rsa_keypair(key_size: int = 2048) -> Dict[str, Any]:
    """
    Generates a temporary demonstration RSA key pair for local educational use.
    Uses cryptography library's rsa.generate_private_key.
    """
    if key_size not in (1024, 2048):
        key_size = 2048

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()

    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Max payload for 2048-bit RSA with OAEP(SHA-256): 256 - 2*32 - 2 = 190 bytes
    max_bytes = (key_size // 8) - (2 * 32) - 2

    return {
        "public_key_pem": public_pem,
        "private_key_pem": private_pem,
        "key_size_bits": key_size,
        "public_exponent": 65537,
        "max_plaintext_bytes": max_bytes,
    }


def rsa_demo_encrypt(public_key_pem: str, plaintext: str) -> Dict[str, Any]:
    """
    Encrypts a short message with an RSA public key using modern OAEP-SHA256 padding.
    """
    if not isinstance(plaintext, str) or not plaintext.strip():
        raise CryptoLabError("Plaintext message cannot be empty.")
    if not isinstance(public_key_pem, str) or "BEGIN PUBLIC KEY" not in public_key_pem:
        raise CryptoLabError("A valid RSA Public Key (PEM format) is required.")

    plaintext_bytes = plaintext.encode("utf-8")

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as e:
        raise CryptoLabError(f"Invalid public key format: {str(e)}")

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CryptoLabError("Supplied key is not an RSA public key.")

    # Calculate maximum payload size for OAEP with SHA-256
    key_size_bytes = public_key.key_size // 8
    max_bytes = key_size_bytes - 2 * hashes.SHA256.digest_size - 2

    if len(plaintext_bytes) > max_bytes:
        raise CryptoLabError(
            f"Message too long for RSA-{public_key.key_size} OAEP-SHA256. "
            f"Maximum allowed is {max_bytes} bytes; message is {len(plaintext_bytes)} bytes. "
            "In practice, RSA encrypts symmetric keys, not large data."
        )

    try:
        ciphertext = public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return {
            "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
            "ciphertext_hex": ciphertext.hex(),
            "ciphertext_bytes": len(ciphertext),
            "padding_scheme": "OAEP with MGF1(SHA-256) and SHA-256 hash",
        }
    except Exception as e:
        raise CryptoLabError(f"RSA encryption failed: {str(e)}")


def rsa_demo_decrypt(private_key_pem: str, ciphertext_input: str) -> Dict[str, Any]:
    """
    Decrypts an RSA ciphertext using the corresponding private key with OAEP-SHA256.
    """
    if not isinstance(ciphertext_input, str) or not ciphertext_input.strip():
        raise CryptoLabError("Ciphertext cannot be empty.")
    if not isinstance(private_key_pem, str) or "BEGIN PRIVATE KEY" not in private_key_pem:
        raise CryptoLabError("A valid RSA Private Key (PEM format) is required.")

    clean_str = ciphertext_input.strip()

    # Try decoding ciphertext as Base64 or Hex
    ciphertext_bytes = None
    try:
        ciphertext_bytes = base64.b64decode(clean_str, validate=True)
    except Exception:
        try:
            ciphertext_bytes = bytes.fromhex(clean_str)
        except Exception:
            raise CryptoLabError("Ciphertext must be a valid Base64 or Hex-encoded string.")

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
        )
    except Exception as e:
        raise CryptoLabError(f"Invalid private key format: {str(e)}")

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptoLabError("Supplied key is not an RSA private key.")

    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return {
            "decrypted_plaintext": plaintext_bytes.decode("utf-8"),
            "verified": True,
        }
    except Exception:
        raise CryptoLabError(
            "RSA decryption failed. Ensure the matching private key is provided and ciphertext is untampered."
        )


# ==============================================================================
# 4. SHA-256 Demonstration (One-Way Cryptographic Hash Function)
# ==============================================================================

def calculate_sha256(text: str) -> Dict[str, Any]:
    """
    Calculates SHA-256 hash for given text and returns educational details.
    """
    if not isinstance(text, str):
        text = str(text)

    text_bytes = text.encode("utf-8")
    digest_hex = hashlib.sha256(text_bytes).hexdigest()

    # Convert hex digest to 256 binary bits for visualization
    digest_bin = bin(int(digest_hex, 16))[2:].zfill(256)

    return {
        "input_text": text,
        "input_length_chars": len(text),
        "input_length_bytes": len(text_bytes),
        "hash_hex": digest_hex,
        "hash_bin": digest_bin,
        "hash_bits": 256,
        "hash_bytes": 32,
    }


def compare_sha256_avalanche(text1: str, text2: str) -> Dict[str, Any]:
    """
    Demonstrates the Avalanche Effect in cryptographic hashing by comparing
    two inputs and calculating the bit-level difference between their digests.
    """
    h1 = calculate_sha256(text1)
    h2 = calculate_sha256(text2)

    bin1 = h1["hash_bin"]
    bin2 = h2["hash_bin"]

    # Calculate Hamming distance (number of bit differences)
    bit_differences = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))
    bit_difference_pct = round((bit_differences / 256) * 100, 2)

    # Character differences in hex digest
    hex1 = h1["hash_hex"]
    hex2 = h2["hash_hex"]
    hex_differences = sum(c1 != c2 for c1, c2 in zip(hex1, hex2))

    return {
        "input1": h1,
        "input2": h2,
        "bit_differences": bit_differences,
        "total_bits": 256,
        "bit_difference_pct": bit_difference_pct,
        "hex_differences": hex_differences,
        "total_hex_chars": 64,
        "is_avalanche_demonstrated": bit_difference_pct >= 40.0,
    }
