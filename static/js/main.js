/**
 * SecureStego — Main Client JavaScript
 * Handles image previews, dynamic capacity estimation, password toggling,
 * copy-to-clipboard, and loading indicators.
 */

document.addEventListener("DOMContentLoaded", function () {
    initPasswordToggles();
    initHidePageEnhancements();
    initRevealPageEnhancements();
    initTooltips();
});

/**
 * Initializes toggle show/hide visibility for password inputs
 */
function initPasswordToggles() {
    const toggleButtons = document.querySelectorAll(".toggle-password");
    toggleButtons.forEach(button => {
        button.addEventListener("click", function () {
            const targetId = this.getAttribute("data-target");
            const input = document.getElementById(targetId);
            if (!input) return;

            const icon = this.querySelector("i");
            if (input.type === "password") {
                input.type = "text";
                if (icon) {
                    icon.classList.remove("bi-eye");
                    icon.classList.add("bi-eye-slash");
                }
            } else {
                input.type = "password";
                if (icon) {
                    icon.classList.remove("bi-eye-slash");
                    icon.classList.add("bi-eye");
                }
            }
        });
    });
}

/**
 * Initializes image preview, capacity calculator, and password match on /hide
 */
function initHidePageEnhancements() {
    const imageInput = document.getElementById("image-input");
    const previewContainer = document.getElementById("image-preview-container");
    const previewImg = document.getElementById("image-preview");
    const previewFilename = document.getElementById("preview-filename");
    const previewDims = document.getElementById("preview-dims");
    const previewCapacity = document.getElementById("preview-capacity");

    const messageTextarea = document.getElementById("secret-message");
    const charCounter = document.getElementById("char-counter");

    const passwordInput = document.getElementById("password-input");
    const confirmPasswordInput = document.getElementById("confirm-password-input");
    const matchFeedback = document.getElementById("password-match-feedback");

    const hideForm = document.getElementById("hide-form");
    const submitBtn = document.getElementById("btn-submit-hide");
    const spinner = document.getElementById("hide-spinner");
    const btnIcon = document.getElementById("hide-btn-icon");
    const btnText = document.getElementById("hide-btn-text");

    let currentMaxCapacityBytes = 0;

    // Handle Image Selection and Client Preview
    if (imageInput && previewContainer && previewImg) {
        imageInput.addEventListener("change", function (e) {
            const file = e.target.files[0];
            if (!file) {
                previewContainer.classList.add("d-none");
                return;
            }

            // Check file type
            if (!file.name.toLowerCase().endsWith(".png") && file.type !== "image/png") {
                alert("Please select a PNG (.png) image file.");
                imageInput.value = "";
                previewContainer.classList.add("d-none");
                return;
            }

            previewFilename.textContent = file.name;
            const objectUrl = URL.createObjectURL(file);
            previewImg.src = objectUrl;
            previewContainer.classList.remove("d-none");

            // Calculate image dimensions and theoretical LSB capacity
            const tempImg = new Image();
            tempImg.onload = function () {
                const width = tempImg.naturalWidth;
                const height = tempImg.naturalHeight;
                const totalPixels = width * height;
                // 3 bits per pixel (1 bit for R, G, B)
                // 8 bytes metadata header (4 bytes magic + 4 bytes length)
                const totalBits = totalPixels * 3;
                const totalBytes = Math.floor(totalBits / 8);
                const maxPayloadBytes = Math.max(0, totalBytes - 8);
                currentMaxCapacityBytes = maxPayloadBytes;

                const formattedCapacity = formatBytes(maxPayloadBytes);
                previewDims.textContent = `Dimensions: ${width} × ${height} px (${totalPixels.toLocaleString()} pixels)`;
                previewCapacity.innerHTML = `<i class="bi bi-database me-1"></i> Max Payload Capacity: <strong>${formattedCapacity}</strong> (${maxPayloadBytes.toLocaleString()} bytes)`;

                updateMessageCounter();
            };
            tempImg.src = objectUrl;
        });
    }

    // Live Message Character / Byte Counter
    function updateMessageCounter() {
        if (!messageTextarea || !charCounter) return;
        const text = messageTextarea.value;
        const charCount = text.length;
        const byteCount = new TextEncoder().encode(text).length;

        // AES-GCM adds 16 bytes salt + 12 bytes nonce + 16 bytes tag = 44 bytes overhead
        const estimatedEncryptedBytes = byteCount > 0 ? byteCount + 44 : 0;

        let statusText = `${charCount} characters (${byteCount} bytes)`;
        if (currentMaxCapacityBytes > 0 && byteCount > 0) {
            const pct = ((estimatedEncryptedBytes / currentMaxCapacityBytes) * 100).toFixed(2);
            if (estimatedEncryptedBytes > currentMaxCapacityBytes) {
                statusText += ` — <span class="text-danger fw-bold">Exceeds capacity! (${pct}%)</span>`;
            } else {
                statusText += ` — <span class="text-azure">${pct}% of image capacity</span>`;
            }
        }
        charCounter.innerHTML = statusText;
    }

    if (messageTextarea) {
        messageTextarea.addEventListener("input", updateMessageCounter);
    }

    // Password Match Feedback
    function checkPasswordMatch() {
        if (!passwordInput || !confirmPasswordInput || !matchFeedback) return;
        const pass = passwordInput.value;
        const confirm = confirmPasswordInput.value;

        if (!confirm) {
            matchFeedback.textContent = "";
            return;
        }

        if (pass === confirm) {
            matchFeedback.textContent = "✓ Passwords match";
            matchFeedback.className = "form-text small text-success";
        } else {
            matchFeedback.textContent = "✕ Passwords do not match";
            matchFeedback.className = "form-text small text-danger";
        }
    }

    if (passwordInput && confirmPasswordInput) {
        passwordInput.addEventListener("input", checkPasswordMatch);
        confirmPasswordInput.addEventListener("input", checkPasswordMatch);
    }

    // Submit Loading State
    if (hideForm && submitBtn && spinner) {
        hideForm.addEventListener("submit", function () {
            spinner.classList.remove("d-none");
            if (btnIcon) btnIcon.classList.add("d-none");
            if (btnText) btnText.textContent = "Encrypting & Embedding...";
            submitBtn.disabled = true;
            // Let the form submit natively
            hideForm.submit();
        });
    }
}

/**
 * Initializes image preview and clipboard copy on /reveal
 */
function initRevealPageEnhancements() {
    const revealInput = document.getElementById("reveal-image-input");
    const previewContainer = document.getElementById("reveal-preview-container");
    const previewImg = document.getElementById("reveal-preview");
    const previewFilename = document.getElementById("reveal-filename");
    const previewDims = document.getElementById("reveal-file-dims");

    const revealForm = document.getElementById("reveal-form");
    const submitBtn = document.getElementById("btn-submit-reveal");
    const spinner = document.getElementById("reveal-spinner");
    const btnIcon = document.getElementById("reveal-btn-icon");
    const btnText = document.getElementById("reveal-btn-text");

    const copyBtn = document.getElementById("btn-copy-message");
    const textBox = document.getElementById("revealed-text-box");
    const clearBtn = document.getElementById("btn-clear-reveal");

    // Stego Image Preview
    if (revealInput && previewContainer && previewImg) {
        revealInput.addEventListener("change", function (e) {
            const file = e.target.files[0];
            if (!file) {
                previewContainer.classList.add("d-none");
                return;
            }

            if (!file.name.toLowerCase().endsWith(".png") && file.type !== "image/png") {
                alert("Please select a PNG (.png) image file.");
                revealInput.value = "";
                previewContainer.classList.add("d-none");
                return;
            }

            previewFilename.textContent = file.name;
            const objectUrl = URL.createObjectURL(file);
            previewImg.src = objectUrl;
            previewContainer.classList.remove("d-none");

            const tempImg = new Image();
            tempImg.onload = function () {
                if (previewDims) {
                    previewDims.textContent = `Carrier Size: ${tempImg.naturalWidth} × ${tempImg.naturalHeight} px`;
                }
            };
            tempImg.src = objectUrl;
        });
    }

    // Copy to Clipboard
    if (copyBtn && textBox) {
        copyBtn.addEventListener("click", function () {
            const textToCopy = textBox.value;
            if (!textToCopy) return;

            navigator.clipboard.writeText(textToCopy).then(() => {
                const copyText = document.getElementById("copy-text");
                const copyIcon = document.getElementById("copy-icon");
                if (copyText) copyText.textContent = "Copied!";
                if (copyIcon) {
                    copyIcon.className = "bi bi-check-lg text-success";
                }

                setTimeout(() => {
                    if (copyText) copyText.textContent = "Copy Message";
                    if (copyIcon) copyIcon.className = "bi bi-clipboard";
                }, 2000);
            }).catch(() => {
                // Fallback for older browsers
                textBox.select();
                document.execCommand("copy");
            });
        });
    }

    // Clear Form
    if (clearBtn && revealForm) {
        clearBtn.addEventListener("click", function () {
            revealForm.reset();
            if (previewContainer) previewContainer.classList.add("d-none");
            if (previewImg) previewImg.src = "#";
        });
    }

    // Submit Loading State
    if (revealForm && submitBtn && spinner) {
        revealForm.addEventListener("submit", function () {
            spinner.classList.remove("d-none");
            if (btnIcon) btnIcon.classList.add("d-none");
            if (btnText) btnText.textContent = "Extracting & Decrypting...";
            submitBtn.disabled = true;
            revealForm.submit();
        });
    }
}

/**
 * Format raw bytes into human readable KB / MB
 */
function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

/**
 * Initialize Bootstrap tooltips
 */
function initTooltips() {
    if (typeof bootstrap !== "undefined" && bootstrap.Tooltip) {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
}
