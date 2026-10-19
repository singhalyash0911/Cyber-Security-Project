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
