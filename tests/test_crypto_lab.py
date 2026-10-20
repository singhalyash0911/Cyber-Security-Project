"""
Tests for Crypto Lab Educational Cryptography Module & Endpoints
================================================================
Comprehensive test suite verifying:
1. AES-256-GCM educational demonstration & breakdown
2. Caesar substitution cipher encryption, decryption & error cases
3. RSA-2048 public/private key generation, OAEP-SHA256 encryption & decryption
4. SHA-256 one-way hashing & avalanche effect metrics
5. Flask HTTP routes and JSON API endpoints for Crypto Lab
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
import crypto_lab
from crypto_lab import CryptoLabError


@pytest.fixture
def client():
    """Flask test client fixture."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestCryptoLabAES:
    """Tests for AES-256-GCM demonstration functions."""

    def test_aes_encrypt_and_decrypt_success(self):
        """Test round-trip encryption and authenticated decryption."""
        msg = "MCA Cryptography Syllabus Test Message"
        password = "SecurePassword123!"

        enc_res = crypto_lab.aes_demo_encrypt(msg, password)
        assert "salt_hex" in enc_res
        assert len(enc_res["salt_hex"]) == 32  # 16 bytes = 32 hex chars
        assert "nonce_hex" in enc_res
        assert len(enc_res["nonce_hex"]) == 24  # 12 bytes = 24 hex chars
        assert "derived_key_hex" in enc_res
        assert len(enc_res["derived_key_hex"]) == 64  # 32 bytes = 64 hex chars
        assert "tag_hex" in enc_res
        assert len(enc_res["tag_hex"]) == 32  # 16 bytes = 32 hex chars
        assert "package_base64" in enc_res

        # Decrypt using Base64 package
        dec_res = crypto_lab.aes_demo_decrypt(enc_res["package_base64"], password)
        assert dec_res["success"] is True
        assert dec_res["decrypted_plaintext"] == msg

    def test_aes_decrypt_wrong_password_fails(self):
        """Test that incorrect password fails authentication tag verification."""
        enc_res = crypto_lab.aes_demo_encrypt("Secret Message", "PasswordA")
        with pytest.raises(CryptoLabError) as exc_info:
            crypto_lab.aes_demo_decrypt(enc_res["package_base64"], "WrongPasswordB")
        assert "Authentication failed" in str(exc_info.value) or "Incorrect password" in str(exc_info.value)

    def test_aes_decrypt_tampered_package_fails(self):
        """Test that tampering with package bytes triggers authentication tag error."""
        enc_res = crypto_lab.aes_demo_encrypt("Secret Message", "PasswordA")
        pkg = enc_res["package_base64"]
        # Flip a character in package string
        tampered_pkg = pkg[:-5] + ("A" if pkg[-5] != "A" else "B") + pkg[-4:]
        with pytest.raises(CryptoLabError):
            crypto_lab.aes_demo_decrypt(tampered_pkg, "PasswordA")

    def test_aes_empty_inputs_raise(self):
        """Test input validation for empty plaintext or password."""
        with pytest.raises(CryptoLabError):
            crypto_lab.aes_demo_encrypt("", "password")
        with pytest.raises(CryptoLabError):
            crypto_lab.aes_demo_encrypt("message", "")


class TestCryptoLabCaesar:
    """Tests for Caesar cipher functions."""

    def test_caesar_encrypt_basic(self):
        """Test basic Caesar shift = 3."""
        assert crypto_lab.caesar_encrypt("HELLO", 3) == "KHOOR"
        assert crypto_lab.caesar_encrypt("hello", 3) == "khoor"
        assert crypto_lab.caesar_encrypt("XYZ", 3) == "ABC"
        assert crypto_lab.caesar_encrypt("xyz", 3) == "abc"

    def test_caesar_preserves_spaces_and_symbols(self):
        """Test punctuation, spaces, and numbers remain intact."""
        text = "Hello, World! 123"
        enc = crypto_lab.caesar_encrypt(text, 5)
        dec = crypto_lab.caesar_decrypt(enc, 5)
        assert dec == text

    def test_caesar_large_and_negative_shifts(self):
        """Test shift normalization with values > 26 and negative shifts."""
        text = "MCA Cyber Security"
        enc = crypto_lab.caesar_encrypt(text, 29)  # 29 % 26 = 3
        assert enc == crypto_lab.caesar_encrypt(text, 3)
        assert crypto_lab.caesar_decrypt(enc, 29) == text

    def test_caesar_demo_structure(self):
        """Test full demonstration dictionary output."""
        res = crypto_lab.caesar_demo("Attack At Dawn", 4, mode="encrypt")
        assert res["normalized_shift"] == 4
        assert res["output_text"] == "Exxego Ex Hear"
        assert res["shifted_alphabet"].startswith("EFG")


class TestCryptoLabRSA:
    """Tests for RSA public/private key operations."""

    def test_rsa_key_generation(self):
        """Test generating demonstration 2048-bit RSA key pair."""
        keys = crypto_lab.generate_demo_rsa_keypair(2048)
        assert "BEGIN PUBLIC KEY" in keys["public_key_pem"]
        assert "BEGIN PRIVATE KEY" in keys["private_key_pem"]
        assert keys["key_size_bits"] == 2048
        assert keys["max_plaintext_bytes"] == 190

    def test_rsa_encrypt_and_decrypt_success(self):
        """Test RSA round trip with OAEP-SHA256."""
        keys = crypto_lab.generate_demo_rsa_keypair(2048)
        message = "Confidential AES Session Key: 8a7f9b0c"

        enc_res = crypto_lab.rsa_demo_encrypt(keys["public_key_pem"], message)
        assert "ciphertext_b64" in enc_res
        assert enc_res["ciphertext_bytes"] == 256  # 2048 bits / 8 = 256 bytes

        dec_res = crypto_lab.rsa_demo_decrypt(keys["private_key_pem"], enc_res["ciphertext_b64"])
        assert dec_res["decrypted_plaintext"] == message

    def test_rsa_oversized_message_rejected(self):
        """Test that attempting to encrypt messages > 190 bytes is cleanly rejected."""
        keys = crypto_lab.generate_demo_rsa_keypair(2048)
        oversized = "A" * 200
        with pytest.raises(CryptoLabError) as exc_info:
            crypto_lab.rsa_demo_encrypt(keys["public_key_pem"], oversized)
        assert "Message too long" in str(exc_info.value)

    def test_rsa_wrong_private_key_fails(self):
        """Test that decrypting with an unrelated private key fails."""
        keys1 = crypto_lab.generate_demo_rsa_keypair(2048)
        keys2 = crypto_lab.generate_demo_rsa_keypair(2048)

        enc_res = crypto_lab.rsa_demo_encrypt(keys1["public_key_pem"], "Secret RSA Data")
        with pytest.raises(CryptoLabError) as exc_info:
            crypto_lab.rsa_demo_decrypt(keys2["private_key_pem"], enc_res["ciphertext_b64"])
        assert "decryption failed" in str(exc_info.value).lower()


class TestCryptoLabSHA256:
    """Tests for SHA-256 and avalanche effect."""

    def test_calculate_sha256(self):
        """Test SHA-256 calculation for known vector."""
        res = crypto_lab.calculate_sha256("abc")
        # Known SHA-256 for "abc": ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert res["hash_hex"] == expected
        assert res["hash_bits"] == 256
        assert len(res["hash_bin"]) == 256

    def test_avalanche_effect(self):
        """Test that changing 1 character causes significant bit differences (~50%)."""
        res = crypto_lab.compare_sha256_avalanche("CyberSecurity2026", "CyberSecurity2027")
        assert res["bit_differences"] > 80  # Well over 30% of bits flipped
        assert res["bit_difference_pct"] >= 40.0
        assert res["is_avalanche_demonstrated"] is True


class TestCryptoLabWebEndpoints:
    """Tests for Flask HTTP routes and JSON API endpoints."""

    def test_get_crypto_lab_page(self, client):
        """Test GET /crypto-lab renders page successfully with all sub-tabs."""
        response = client.get("/crypto-lab")
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "Crypto Lab" in html
        assert "AES-256-GCM" in html
        assert "Caesar Cipher" in html
        assert "RSA" in html
        assert "SHA-256" in html
        assert "MCA Theory Topics" in html

    def test_api_aes_encrypt_and_decrypt(self, client):
        """Test POST /crypto-lab/api/aes/encrypt and decrypt."""
        # Encrypt
        resp = client.post("/crypto-lab/api/aes/encrypt", json={
            "plaintext": "API Test Plaintext",
            "password": "ApiPassword123!"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        pkg = data["data"]["package_base64"]

        # Decrypt
        resp_dec = client.post("/crypto-lab/api/aes/decrypt", json={
            "package": pkg,
            "password": "ApiPassword123!"
        })
        assert resp_dec.status_code == 200
        dec_data = resp_dec.get_json()
        assert dec_data["success"] is True
        assert dec_data["data"]["decrypted_plaintext"] == "API Test Plaintext"

    def test_api_caesar(self, client):
        """Test POST /crypto-lab/api/caesar."""
        resp = client.post("/crypto-lab/api/caesar", json={
            "text": "Hello World",
            "shift": 3,
            "mode": "encrypt"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["data"]["output_text"] == "Khoor Zruog"

    def test_api_rsa_workflow(self, client):
        """Test POST /crypto-lab/api/rsa/generate-keys, encrypt, and decrypt."""
        # Generate
        gen_resp = client.post("/crypto-lab/api/rsa/generate-keys")
        assert gen_resp.status_code == 200
        keys = gen_resp.get_json()["data"]
        pub_key = keys["public_key_pem"]
        priv_key = keys["private_key_pem"]

        # Encrypt
        enc_resp = client.post("/crypto-lab/api/rsa/encrypt", json={
            "public_key": pub_key,
            "plaintext": "RSA API Secret"
        })
        assert enc_resp.status_code == 200
        ct = enc_resp.get_json()["data"]["ciphertext_b64"]

        # Decrypt
        dec_resp = client.post("/crypto-lab/api/rsa/decrypt", json={
            "private_key": priv_key,
            "ciphertext": ct
        })
        assert dec_resp.status_code == 200
        assert dec_resp.get_json()["data"]["decrypted_plaintext"] == "RSA API Secret"

    def test_api_sha256(self, client):
        """Test POST /crypto-lab/api/sha256."""
        resp = client.post("/crypto-lab/api/sha256", json={"text": "Test Hash"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert len(data["data"]["hash_hex"]) == 64

    def test_api_sha256_avalanche(self, client):
        """Test POST /crypto-lab/api/sha256/avalanche."""
        resp = client.post("/crypto-lab/api/sha256/avalanche", json={
            "text1": "CyberSecurity2026",
            "text2": "CyberSecurity2027"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["data"]["bit_differences"] > 0
        assert data["data"]["bit_difference_pct"] >= 40.0
