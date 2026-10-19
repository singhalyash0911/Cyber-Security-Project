"""
Tests for SecureStego Steganography Module
==========================================
Covers LSB embedding and extraction, capacity validation, format checks,
header detection, and integration with the encryption module.
"""

import io
import pytest
import os
import sys
from PIL import Image

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from steganography import (
    embed_payload,
    extract_payload,
    inspect_image,
    SteganographyError,
    CapacityError,
    MAGIC_HEADER
)
from encryption import encrypt_message, decrypt_message


def create_dummy_png(width: int = 100, height: int = 100, mode: str = "RGB", color=(120, 150, 180)) -> io.BytesIO:
    """Helper to create an in-memory PNG image for testing."""
    if mode == "RGBA":
        color = (color[0], color[1], color[2], 255)
    img = Image.new(mode, (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


class TestSteganography:
    """Test suite for LSB steganography operations."""

    def test_inspect_valid_png(self):
        """Test metadata extraction for valid PNG images."""
        png_buf = create_dummy_png(200, 150, "RGB")
        img, metadata = inspect_image(png_buf)

        assert metadata["width"] == 200
        assert metadata["height"] == 150
        assert metadata["total_pixels"] == 30000
        # 30,000 pixels * 3 channels = 90,000 bits = 11,250 bytes
        assert metadata["total_capacity_bytes"] == 11250
        assert metadata["max_payload_bytes"] == 11250 - 8

    def test_reject_non_png_format(self):
        """Test that non-PNG image formats (e.g. JPEG) are strictly rejected."""
        img = Image.new("RGB", (100, 100), color=(255, 0, 0))
        jpeg_buf = io.BytesIO()
        img.save(jpeg_buf, format="JPEG")
        jpeg_buf.seek(0)

        with pytest.raises(SteganographyError) as exc_info:
            inspect_image(jpeg_buf)
        assert "Only PNG images are supported" in str(exc_info.value)

    def test_embed_and_extract_roundtrip_rgb(self):
        """Test round-trip embedding and extracting raw bytes in an RGB PNG."""
        original_payload = b"Hello, this is a secret payload stored inside pixels!"
        png_buf = create_dummy_png(150, 150, "RGB")

        # Embed
        stego_buf = embed_payload(png_buf, original_payload)
        assert isinstance(stego_buf, io.BytesIO)

        # Extract
        extracted_payload = extract_payload(stego_buf)
        assert extracted_payload == original_payload

    def test_embed_and_extract_roundtrip_rgba(self):
        """Test round-trip on an RGBA PNG and ensure alpha channel is preserved."""
        original_payload = b"Payload in RGBA image"
        png_buf = create_dummy_png(100, 100, "RGBA")

        stego_buf = embed_payload(png_buf, original_payload)
        extracted_payload = extract_payload(stego_buf)
        assert extracted_payload == original_payload

        # Verify alpha values remained untouched
        stego_img = Image.open(stego_buf)
        assert stego_img.mode == "RGBA"
        # Check first pixel alpha
        assert stego_img.getpixel((0, 0))[3] == 255

    def test_capacity_exceeded_rejected(self):
        """Test that attempting to hide data larger than image capacity raises CapacityError."""
        # 10x10 image = 100 pixels * 3 bits = 300 bits = 37 bytes total
        # Metadata = 8 bytes -> max payload = 29 bytes
        small_png = create_dummy_png(10, 10, "RGB")
        oversized_payload = b"A" * 100  # 100 bytes > 29 bytes

        with pytest.raises(CapacityError) as exc_info:
            embed_payload(small_png, oversized_payload)
        assert "exceeds image capacity" in str(exc_info.value)

    def test_extract_ordinary_image_rejected(self):
        """Test that an ordinary image without SecureStego header is rejected with clear error."""
        clean_png = create_dummy_png(100, 100, "RGB")

        with pytest.raises(SteganographyError) as exc_info:
            extract_payload(clean_png)
        assert "No SecureStego hidden message found" in str(exc_info.value)

    def test_end_to_end_encryption_and_steganography(self):
        """Test full pipeline: Encrypt -> Embed -> Extract -> Decrypt."""
        secret_text = "MCA Cyber Security Project: End-to-End Stego & Crypto Verified! 🚀"
        password = "ProjectDemoPassword2026@"

        # Step 1: Encrypt
        encrypted_package = encrypt_message(secret_text, password)

        # Step 2: Embed into PNG
        carrier_image = create_dummy_png(200, 200, "RGB")
        stego_image = embed_payload(carrier_image, encrypted_package)

        # Step 3: Extract from Stego PNG
        recovered_package = extract_payload(stego_image)
        assert recovered_package == encrypted_package

        # Step 4: Decrypt with correct password
        recovered_text = decrypt_message(recovered_package, password)
        assert recovered_text == secret_text

    def test_end_to_end_wrong_password_fails(self):
        """Test full pipeline fails during decryption when wrong password is supplied."""
        secret_text = "Highly sensitive confidential data"
        password = "SecretPassword1"
        wrong_password = "SecretPassword2"

        encrypted = encrypt_message(secret_text, password)
        carrier_image = create_dummy_png(150, 150, "RGB")
        stego_image = embed_payload(carrier_image, encrypted)

        recovered_package = extract_payload(stego_image)

        # Decrypting with wrong password must fail
        from encryption import DecryptionError
        with pytest.raises(DecryptionError):
            decrypt_message(recovered_package, wrong_password)
