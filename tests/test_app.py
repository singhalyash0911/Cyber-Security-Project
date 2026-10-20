"""
Tests for SecureStego Flask Web Application
============================================
Covers all 4 web routes, form validation, error handling,
end-to-end hide and reveal HTTP workflows, and flash messages.
"""

import io
import os
import sys
import pytest
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app


@pytest.fixture
def client():
    """Flask test client fixture."""
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client


def make_test_png(width=120, height=120, color=(100, 150, 200)):
    """Creates an in-memory PNG file object for HTTP file upload simulation."""
    img = Image.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


class TestWebRoutes:
    """Tests for all GET page routes."""

    def test_home_page(self, client):
        """Test GET / renders successfully with core elements."""
        response = client.get("/")
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "SecureStego" in html
        assert "Hide a Message" in html
        assert "Reveal a Message" in html
        assert "Steganography" in html
        assert "Encryption" in html

    def test_hide_page_get(self, client):
        """Test GET /hide renders the embedding form."""
        response = client.get("/hide")
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "Hide a Message in Image" in html
        assert "Secret Message" in html
        assert "Encryption Password" in html

    def test_reveal_page_get(self, client):
        """Test GET /reveal renders the extraction form."""
        response = client.get("/reveal")
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "Reveal a Hidden Message" in html
        assert "Decryption Password" in html

    def test_about_page_get(self, client):
        """Test GET /about renders the architecture and viva guide."""
        response = client.get("/about")
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "End-to-End System Workflow" in html
        assert "AES-256-GCM" in html
        assert "PBKDF2-HMAC-SHA256" in html
        assert "LSB Steganography" in html
        assert "Student 1" in html
        assert "Student 2" in html
        assert "Student 3" in html

    def test_crypto_lab_page_get(self, client):
        """Test GET /crypto-lab renders the syllabus lab demonstrations."""
        response = client.get("/crypto-lab")
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "Crypto Lab" in html
        assert "AES-256-GCM" in html
        assert "Caesar Cipher" in html
        assert "RSA" in html
        assert "SHA-256" in html
        assert "MCA Theory Topics" in html


class TestHideWorkflow:
    """Tests for POST /hide validation and stego image generation."""

    def test_hide_missing_file(self, client):
        """Test validation when no file is uploaded."""
        response = client.post("/hide", data={
            "message": "Top Secret",
            "password": "Password123",
            "confirm_password": "Password123"
        }, follow_redirects=True)
        assert response.status_code == 200
        assert "Please select a PNG image file" in response.data.decode("utf-8")

    def test_hide_invalid_extension(self, client):
        """Test validation when non-PNG file is uploaded."""
        fake_file = (io.BytesIO(b"not an image"), "sample.txt")
        response = client.post("/hide", data={
            "image": fake_file,
            "message": "Top Secret",
            "password": "Password123",
            "confirm_password": "Password123"
        }, follow_redirects=True)
        assert response.status_code == 200
        assert "Only PNG (.png) images are supported" in response.data.decode("utf-8")

    def test_hide_empty_message(self, client):
        """Test validation when secret message is blank."""
        png = make_test_png()
        response = client.post("/hide", data={
            "image": (png, "carrier.png"),
            "message": "   ",
            "password": "Password123",
            "confirm_password": "Password123"
        }, follow_redirects=True)
        assert response.status_code == 200
        assert "Secret message cannot be empty" in response.data.decode("utf-8")

    def test_hide_mismatched_passwords(self, client):
        """Test validation when passwords do not match."""
        png = make_test_png()
        response = client.post("/hide", data={
            "image": (png, "carrier.png"),
            "message": "Valid Secret",
            "password": "PasswordOne",
            "confirm_password": "PasswordTwo"
        }, follow_redirects=True)
        assert response.status_code == 200
        assert "Passwords do not match" in response.data.decode("utf-8")

    def test_hide_success(self, client):
        """Test successful hide operation returning base64 stego download."""
        png = make_test_png(150, 150)
        secret = "University MCA Viva Confidential Note"
        password = "VivaSecretKey!2026"

        response = client.post("/hide", data={
            "image": (png, "valid_carrier.png"),
            "message": secret,
            "password": password,
            "confirm_password": password
        })
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "Message Encrypted &amp; Embedded Successfully!" in html
        assert "data:image/png;base64," in html
        assert "Download Stego Image" in html


class TestRevealWorkflow:
    """Tests for POST /reveal workflow, decryption, and error reporting."""

    def test_reveal_missing_file(self, client):
        """Test reveal validation when no image is uploaded."""
        response = client.post("/reveal", data={
            "password": "AnyPassword"
        }, follow_redirects=True)
        assert response.status_code == 200
        assert "Please upload a PNG image" in response.data.decode("utf-8")

    def test_reveal_ordinary_image(self, client):
        """Test error display when image contains no SecureStego payload."""
        png = make_test_png(100, 100)
        response = client.post("/reveal", data={
            "image": (png, "plain.png"),
            "password": "TestPassword"
        })
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "No SecureStego hidden message found" in html

    def test_full_hide_and_reveal_roundtrip(self, client):
        """Test full end-to-end web round-trip: hide via POST /hide and reveal via POST /reveal."""
        import base64

        secret = "MCA 3rd-Semester Final Cyber Project: End-to-End Success!"
        password = "SecureGroupPassword#2026"

        # 1. Post to /hide
        png = make_test_png(150, 150)
        hide_response = client.post("/hide", data={
            "image": (png, "original.png"),
            "message": secret,
            "password": password,
            "confirm_password": password
        })
        assert hide_response.status_code == 200
        hide_html = hide_response.data.decode("utf-8")

        # Extract base64 image data URL from response
        marker = 'data:image/png;base64,'
        start_idx = hide_html.find(marker)
        assert start_idx != -1
        start_data = start_idx + len(marker)
        end_idx = hide_html.find('"', start_data)
        b64_data = hide_html[start_data:end_idx]

        stego_png_bytes = base64.b64decode(b64_data)

        # 2. Post to /reveal with CORRECT password
        reveal_response = client.post("/reveal", data={
            "image": (io.BytesIO(stego_png_bytes), "stego_downloaded.png"),
            "password": password
        })
        assert reveal_response.status_code == 200
        reveal_html = reveal_response.data.decode("utf-8")
        assert "Decryption &amp; Authentication Successful!" in reveal_html
        assert secret in reveal_html

        # 3. Post to /reveal with INCORRECT password
        wrong_response = client.post("/reveal", data={
            "image": (io.BytesIO(stego_png_bytes), "stego_downloaded.png"),
            "password": "WrongPasswordEntered"
        })
        assert wrong_response.status_code == 200
        wrong_html = wrong_response.data.decode("utf-8")
        assert "Authentication failed" in wrong_html
        assert secret not in wrong_html
