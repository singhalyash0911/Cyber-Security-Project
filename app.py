"""
SecureStego — Main Flask Application
=====================================
A beginner-friendly cybersecurity web application demonstrating
AES-256-GCM encryption and LSB image steganography.

MCA 3rd-Semester Cyber Security Academic Project.
Student Responsibility: Student 3 (Web Application Architecture & UI)
"""

import os
import io
import base64
from flask import (
    Flask,
    render_template,
    request,
    flash,
    redirect,
    url_for,
    jsonify,
    Response,
    send_file
)
from werkzeug.utils import secure_filename
from PIL import Image

from encryption import (
    encrypt_message,
    decrypt_message,
    EncryptionError,
    DecryptionError
)
from steganography import (
    embed_payload,
    extract_payload,
    inspect_image,
    SteganographyError,
    CapacityError
)
from crypto_lab import (
    aes_demo_encrypt,
    aes_demo_decrypt,
    caesar_demo,
    generate_demo_rsa_keypair,
    rsa_demo_encrypt,
    rsa_demo_decrypt,
    calculate_sha256,
    compare_sha256_avalanche,
    CryptoLabError
)

app = Flask(__name__)

# Cryptographically secure random session secret key for flash messages
app.secret_key = os.urandom(32)

# Enforce sensible maximum upload size (16 MB)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 Megabytes
app.config["TEMPLATES_AUTO_RELOAD"] = True

ALLOWED_EXTENSIONS = {"png"}


def is_allowed_file(filename: str) -> bool:
    """Validates that the uploaded filename ends with an allowed PNG extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
def index():
    """Page 1: Home — Landing page introducing SecureStego."""
    return render_template("index.html", title="Home — SecureStego")


@app.route("/hide", methods=["GET", "POST"])
def hide():
    """
    Page 2: Hide Message.
    - GET: Displays the message embedding form.
    - POST: Validates PNG image, encrypts message with AES-256-GCM,
            embeds encrypted payload via LSB, and provides stego image for download.
    """
    if request.method == "POST":
        image_file = request.files.get("image")
        secret_message = request.form.get("message", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # --- Input Validation ---
        if not image_file or image_file.filename == "":
            flash("Please select a PNG image file to embed your message.", "danger")
            return redirect(url_for("hide"))

        if not is_allowed_file(image_file.filename):
            flash("Invalid file format. Only PNG (.png) images are supported.", "danger")
            return redirect(url_for("hide"))

        if not secret_message:
            flash("Secret message cannot be empty.", "danger")
            return redirect(url_for("hide"))

        if not password:
            flash("Please provide a password to protect your message.", "danger")
            return redirect(url_for("hide"))

        if password != confirm_password:
            flash("Passwords do not match. Please re-enter matching passwords.", "danger")
            return redirect(url_for("hide"))

        try:
            # Read image file in-memory
            image_bytes = image_file.read()

            # Verify image format and get capacity info
            img, metadata = inspect_image(image_bytes)

            # Step 1: Encrypt plaintext using AES-256-GCM + PBKDF2
            encrypted_package = encrypt_message(secret_message, password)

            # Step 2: Embed encrypted package into image using LSB steganography
            stego_buffer = embed_payload(image_bytes, encrypted_package)

            # Convert resulting stego image to base64 for preview and direct download
            stego_bytes = stego_buffer.getvalue()
            stego_b64 = base64.b64encode(stego_bytes).decode("utf-8")
            data_url = f"data:image/png;base64,{stego_b64}"

            # Calculate payload and capacity statistics
            payload_size = len(encrypted_package)
            total_capacity = metadata["max_payload_bytes"]
            capacity_percent = round((payload_size / total_capacity) * 100, 2) if total_capacity > 0 else 100

            result_data = {
                "success": True,
                "data_url": data_url,
                "filename": f"stego_{secure_filename(image_file.filename)}",
                "width": metadata["width"],
                "height": metadata["height"],
                "payload_size": payload_size,
                "total_capacity": total_capacity,
                "capacity_percent": capacity_percent,
                "original_message_length": len(secret_message)
            }

            flash("Success! Message was encrypted with AES-256-GCM and embedded into the PNG image.", "success")
            return render_template("hide.html", title="Hide Message — SecureStego", result=result_data)

        except CapacityError as ce:
            flash(f"Capacity Error: {str(ce)}", "warning")
            return redirect(url_for("hide"))
        except (EncryptionError, SteganographyError) as se:
            flash(f"Processing Error: {str(se)}", "danger")
            return redirect(url_for("hide"))
        except Exception as e:
            # Safe generic error message avoiding technical trace leaks
            flash("An unexpected error occurred while processing the image. Please verify your file and try again.", "danger")
            return redirect(url_for("hide"))

    return render_template("hide.html", title="Hide Message — SecureStego", result=None)


@app.route("/reveal", methods=["GET", "POST"])
def reveal():
    """
    Page 3: Reveal Message.
    - GET: Displays the image extraction form.
    - POST: Extracts LSB payload from uploaded PNG and decrypts with password.
    """
    if request.method == "POST":
        image_file = request.files.get("image")
        password = request.form.get("password", "")

        # --- Input Validation ---
        if not image_file or image_file.filename == "":
            flash("Please upload a PNG image containing a hidden message.", "danger")
            return redirect(url_for("reveal"))

        if not is_allowed_file(image_file.filename):
            flash("Invalid file format. Only PNG (.png) images are supported.", "danger")
            return redirect(url_for("reveal"))

        if not password:
            flash("Please enter the decryption password.", "danger")
            return redirect(url_for("reveal"))

        try:
            image_bytes = image_file.read()

            # Step 1: Extract encrypted binary payload using LSB
            extracted_payload = extract_payload(image_bytes)

            # Step 2: Decrypt payload using AES-256-GCM + PBKDF2
            decrypted_message = decrypt_message(extracted_payload, password)

            flash("Success! Message authenticity verified and decrypted successfully.", "success")
            return render_template(
                "reveal.html",
                title="Reveal Message — SecureStego",
                revealed_message=decrypted_message,
                payload_size=len(extracted_payload)
            )

        except SteganographyError as se:
            flash(str(se), "danger")
            return render_template("reveal.html", title="Reveal Message — SecureStego", revealed_message=None)
        except DecryptionError as de:
            flash(str(de), "danger")
            return render_template("reveal.html", title="Reveal Message — SecureStego", revealed_message=None)
        except Exception:
            flash("Unable to reveal message: Authentication failed or the file is corrupted.", "danger")
            return render_template("reveal.html", title="Reveal Message — SecureStego", revealed_message=None)

    return render_template("reveal.html", title="Reveal Message — SecureStego", revealed_message=None)


@app.route("/crypto-lab")
def crypto_lab():
    """
    Page 5: Crypto Lab — Educational cryptography demonstrations for MCA syllabus.
    Includes AES-256-GCM, Caesar substitution cipher, RSA-2048 with OAEP-SHA256,
    SHA-256 one-way hashing & avalanche effect, and concise theory topics.
    """
    try:
        initial_rsa_keys = generate_demo_rsa_keypair(2048)
    except Exception:
        initial_rsa_keys = None

    active_tab = request.args.get("tab", "aes")
    return render_template(
        "crypto_lab.html",
        title="Crypto Lab — SecureStego",
        initial_rsa_keys=initial_rsa_keys,
        active_tab=active_tab
    )


# --- Crypto Lab Educational API Endpoints ---

@app.route("/crypto-lab/api/aes/encrypt", methods=["POST"])
def api_crypto_aes_encrypt():
    """API endpoint to demonstrate AES-256-GCM encryption with internal breakdown."""
    data = request.get_json(silent=True) or {}
    plaintext = data.get("plaintext", "").strip()
    password = data.get("password", "")

    if not plaintext:
        return jsonify({"success": False, "error": "Plaintext message cannot be empty."}), 400
    if not password:
        return jsonify({"success": False, "error": "Password cannot be empty."}), 400

    try:
        result = aes_demo_encrypt(plaintext, password)
        return jsonify({"success": True, "data": result})
    except (CryptoLabError, EncryptionError) as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": "Encryption failed: " + str(e)}), 500


@app.route("/crypto-lab/api/aes/decrypt", methods=["POST"])
def api_crypto_aes_decrypt():
    """API endpoint to demonstrate AES-256-GCM authenticated decryption."""
    data = request.get_json(silent=True) or {}
    package = data.get("package", "").strip()
    password = data.get("password", "")

    if not package:
        return jsonify({"success": False, "error": "Encrypted package string cannot be empty."}), 400
    if not password:
        return jsonify({"success": False, "error": "Please provide the decryption password."}), 400

    try:
        result = aes_demo_decrypt(package, password)
        return jsonify({"success": True, "data": result})
    except (CryptoLabError, DecryptionError) as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": "Decryption failed: " + str(e)}), 400


@app.route("/crypto-lab/api/caesar", methods=["POST"])
def api_crypto_caesar():
    """API endpoint to demonstrate Caesar substitution cipher encryption/decryption."""
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    shift = data.get("shift", 3)
    mode = data.get("mode", "encrypt")

    if not text:
        return jsonify({"success": False, "error": "Input text cannot be empty."}), 400

    try:
        shift_int = int(shift)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Shift must be a valid integer."}), 400

    try:
        result = caesar_demo(text, shift_int, mode=mode)
        return jsonify({"success": True, "data": result})
    except CryptoLabError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/crypto-lab/api/rsa/generate-keys", methods=["POST"])
def api_crypto_rsa_generate():
    """API endpoint to generate a fresh 2048-bit demonstration RSA key pair."""
    try:
        keys = generate_demo_rsa_keypair(2048)
        return jsonify({"success": True, "data": keys})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to generate RSA keys: {str(e)}"}), 500


@app.route("/crypto-lab/api/rsa/encrypt", methods=["POST"])
def api_crypto_rsa_encrypt():
    """API endpoint to encrypt a short message using RSA public key with OAEP-SHA256."""
    data = request.get_json(silent=True) or {}
    public_key = data.get("public_key", "").strip()
    plaintext = data.get("plaintext", "").strip()

    if not public_key:
        return jsonify({"success": False, "error": "Public key (PEM format) is required."}), 400
    if not plaintext:
        return jsonify({"success": False, "error": "Plaintext message cannot be empty."}), 400

    try:
        result = rsa_demo_encrypt(public_key, plaintext)
        return jsonify({"success": True, "data": result})
    except CryptoLabError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/crypto-lab/api/rsa/decrypt", methods=["POST"])
def api_crypto_rsa_decrypt():
    """API endpoint to decrypt ciphertext using RSA private key with OAEP-SHA256."""
    data = request.get_json(silent=True) or {}
    private_key = data.get("private_key", "").strip()
    ciphertext = data.get("ciphertext", "").strip()

    if not private_key:
        return jsonify({"success": False, "error": "Private key (PEM format) is required."}), 400
    if not ciphertext:
        return jsonify({"success": False, "error": "Ciphertext cannot be empty."}), 400

    try:
        result = rsa_demo_decrypt(private_key, ciphertext)
        return jsonify({"success": True, "data": result})
    except CryptoLabError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/crypto-lab/api/sha256", methods=["POST"])
def api_crypto_sha256():
    """API endpoint to calculate SHA-256 hash digest."""
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    if not text:
        return jsonify({"success": False, "error": "Input text cannot be empty."}), 400

    try:
        result = calculate_sha256(text)
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/crypto-lab/api/sha256/avalanche", methods=["POST"])
def api_crypto_sha256_avalanche():
    """API endpoint to demonstrate SHA-256 avalanche effect by comparing two inputs."""
    data = request.get_json(silent=True) or {}
    text1 = data.get("text1", "")
    text2 = data.get("text2", "")

    if text1 is None or text2 is None:
        return jsonify({"success": False, "error": "Both input texts are required."}), 400

    try:
        result = compare_sha256_avalanche(str(text1), str(text2))
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/about")
def about():
    """Page 4: About and How It Works — Academic concepts and architecture."""
    return render_template("about.html", title="About & How It Works — SecureStego")


@app.route("/api/inspect", methods=["POST"])
def api_inspect():
    """
    Helper API for client-side JavaScript to inspect image dimensions
    and maximum payload capacity as soon as user selects a file.
    """
    image_file = request.files.get("image")
    if not image_file or not is_allowed_file(image_file.filename):
        return jsonify({"success": False, "error": "Invalid PNG image"}), 400

    try:
        image_bytes = image_file.read()
        _, metadata = inspect_image(image_bytes)
        return jsonify({"success": True, "metadata": metadata})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


# --- Global Error Handlers ---
@app.errorhandler(413)
def request_entity_too_large(error):
    """Handles oversized uploads gracefully."""
    flash("The uploaded file is too large. Maximum allowed file size is 16 MB.", "danger")
    return redirect(request.url or url_for("index"))


@app.errorhandler(404)
def not_found_error(error):
    """Custom 404 handler."""
    return render_template("base.html", title="404 - Page Not Found", error_code=404), 404


@app.errorhandler(500)
def internal_error(error):
    """Custom 500 handler without leaking technical stack trace."""
    return render_template("base.html", title="500 - Server Error", error_code=500), 500


if __name__ == "__main__":
    # Local development server
    print("Starting SecureStego application on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
