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
    initCryptoLab();
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

/**
 * Escapes HTML characters to prevent XSS in dynamic DOM inserts
 */
function escapeHtml(text) {
    if (!text) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/**
 * =============================================================================
 * Crypto Lab Client Logic
 * Handles interactive demonstrations for AES-256-GCM, Caesar Cipher, RSA,
 * and SHA-256 Avalanche Effect.
 * =============================================================================
 */
function initCryptoLab() {
    const cryptoTabs = document.getElementById("cryptoLabTabs");
    if (!cryptoTabs) return;

    // Synchronize active tab with URL hash if present (#aes, #caesar, #rsa, #sha256, #theory)
    if (window.location.hash) {
        const hash = window.location.hash.substring(1);
        const targetBtn = document.getElementById(`tab-${hash}`);
        if (targetBtn && typeof bootstrap !== "undefined") {
            const tabInstance = bootstrap.Tab.getOrCreateInstance(targetBtn);
            tabInstance.show();
        }
    }

    initAesDemo();
    initCaesarDemo();
    initRsaDemo();
    initSha256Demo();
}

/**
 * 1. AES-256-GCM Live Demonstration Handler
 */
function initAesDemo() {
    const btnEncrypt = document.getElementById("btn-aes-encrypt");
    const plaintextInput = document.getElementById("aes-plaintext");
    const passwordInput = document.getElementById("aes-password");
    const resultContainer = document.getElementById("aes-result-container");

    const saltEl = document.getElementById("aes-res-salt");
    const keyEl = document.getElementById("aes-res-key");
    const nonceEl = document.getElementById("aes-res-nonce");
    const tagEl = document.getElementById("aes-res-tag");
    const ctEl = document.getElementById("aes-res-ciphertext");
    const ctLenBadge = document.getElementById("aes-res-ct-len");
    const pkgEl = document.getElementById("aes-res-package");
    const btnCopyPkg = document.getElementById("btn-copy-aes-pkg");

    const decPkgInput = document.getElementById("aes-dec-package");
    const decPasswordInput = document.getElementById("aes-dec-password");
    const btnDecrypt = document.getElementById("btn-aes-decrypt");
    const btnTamper = document.getElementById("btn-aes-tamper");
    const decFeedback = document.getElementById("aes-dec-feedback");

    if (btnEncrypt && plaintextInput && passwordInput) {
        btnEncrypt.addEventListener("click", async function () {
            const plaintext = plaintextInput.value.trim();
            const password = passwordInput.value;

            if (!plaintext) {
                alert("Please enter a plaintext message.");
                plaintextInput.focus();
                return;
            }
            if (!password) {
                alert("Please enter a password for AES-256 key derivation.");
                passwordInput.focus();
                return;
            }

            btnEncrypt.disabled = true;
            btnEncrypt.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Encrypting with AES-256-GCM...`;

            try {
                const response = await fetch("/crypto-lab/api/aes/encrypt", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ plaintext, password })
                });
                const res = await response.json();

                if (res.success) {
                    const d = res.data;
                    if (saltEl) saltEl.textContent = d.salt_hex;
                    if (keyEl) keyEl.textContent = d.derived_key_hex;
                    if (nonceEl) nonceEl.textContent = d.nonce_hex;
                    if (tagEl) tagEl.textContent = d.tag_hex;
                    if (ctEl) ctEl.textContent = d.ciphertext_hex;
                    if (ctLenBadge) ctLenBadge.textContent = `${d.ciphertext_bytes} Bytes`;
                    if (pkgEl) pkgEl.textContent = d.package_base64;

                    // Autofill decryption tester
                    if (decPkgInput) decPkgInput.value = d.package_base64;
                    if (decPasswordInput) decPasswordInput.value = password;
                    if (decFeedback) decFeedback.className = "mt-3 d-none";

                    if (resultContainer) resultContainer.classList.remove("d-none");
                } else {
                    alert("Encryption error: " + (res.error || "Failed."));
                }
            } catch (err) {
                alert("Network error: " + err.message);
            } finally {
                btnEncrypt.disabled = false;
                btnEncrypt.innerHTML = `<i class="bi bi-lock-fill me-1"></i> Encrypt with AES-256-GCM`;
            }
        });
    }

    if (btnCopyPkg && pkgEl) {
        btnCopyPkg.addEventListener("click", function () {
            navigator.clipboard.writeText(pkgEl.textContent.trim()).then(() => {
                btnCopyPkg.innerHTML = `<i class="bi bi-check-lg text-success"></i> Copied!`;
                setTimeout(() => {
                    btnCopyPkg.innerHTML = `<i class="bi bi-clipboard"></i> Copy Package`;
                }, 2000);
            });
        });
    }

    if (btnDecrypt && decPkgInput && decPasswordInput) {
        btnDecrypt.addEventListener("click", async function () {
            const pkg = decPkgInput.value.trim();
            const password = decPasswordInput.value;

            if (!pkg || !password) {
                alert("Please provide both the package and password to decrypt.");
                return;
            }

            btnDecrypt.disabled = true;
            btnDecrypt.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Verifying...`;

            try {
                const response = await fetch("/crypto-lab/api/aes/decrypt", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ package: pkg, password: password })
                });
                const res = await response.json();

                if (decFeedback) {
                    decFeedback.classList.remove("d-none");
                    if (res.success) {
                        decFeedback.className = "mt-3 p-3 rounded bg-dark-navy border border-emerald-subtle";
                        decFeedback.innerHTML = `
                            <div class="d-flex align-items-center gap-2 text-success fw-bold mb-1">
                                <i class="bi bi-check-circle-fill fs-5"></i>
                                <span>Authentication Tag Verified &amp; Decryption Successful!</span>
                            </div>
                            <div class="small text-secondary mb-1">Recovered Plaintext:</div>
                            <div class="font-monospace text-white p-2 rounded bg-navy-surface">${escapeHtml(res.data.decrypted_plaintext)}</div>
                        `;
                    } else {
                        decFeedback.className = "mt-3 p-3 rounded bg-dark-navy border border-danger";
                        decFeedback.innerHTML = `
                            <div class="d-flex align-items-center gap-2 text-danger fw-bold mb-1">
                                <i class="bi bi-x-circle-fill fs-5"></i>
                                <span>Decryption / Authentication Failed</span>
                            </div>
                            <p class="small text-secondary mb-0">
                                ${escapeHtml(res.error)}
                            </p>
                        `;
                    }
                }
            } catch (err) {
                alert("Decryption network error: " + err.message);
            } finally {
                btnDecrypt.disabled = false;
                btnDecrypt.innerHTML = `<i class="bi bi-check-circle me-1"></i> Decrypt`;
            }
        });
    }

    if (btnTamper && decPkgInput) {
        btnTamper.addEventListener("click", function () {
            let val = decPkgInput.value.trim();
            if (val.length > 10) {
                // Alter a character near the middle of the base64 package
                const pos = Math.floor(val.length / 2);
                const replacement = val[pos] === 'A' ? 'B' : 'A';
                decPkgInput.value = val.substring(0, pos) + replacement + val.substring(pos + 1);

                if (decFeedback) {
                    decFeedback.classList.remove("d-none");
                    decFeedback.className = "mt-3 p-3 rounded bg-dark-navy border border-warning";
                    decFeedback.innerHTML = `
                        <div class="d-flex align-items-center gap-2 text-warning fw-bold mb-1">
                            <i class="bi bi-lightning-fill"></i>
                            <span>Simulated Tampering Applied!</span>
                        </div>
                        <div class="small text-secondary">
                            A character inside the ciphertext payload was flipped. Click <strong>Decrypt</strong> to see AES-GCM's authentication tag detect the integrity breach and reject the data.
                        </div>
                    `;
                }
            } else {
                alert("Please encrypt a message first to generate a package to tamper with.");
            }
        });
    }
}

/**
 * 2. Caesar Cipher Demonstration Handler
 */
function initCaesarDemo() {
    const input = document.getElementById("caesar-input");
    const slider = document.getElementById("caesar-shift-slider");
    const shiftVal = document.getElementById("caesar-shift-val");
    const shiftAlpha = document.getElementById("caesar-alpha-shift");
    const revShift = document.getElementById("caesar-reverse-shift");
    const output = document.getElementById("caesar-output");
    const btnApply = document.getElementById("btn-caesar-apply");
    const btnRot13 = document.getElementById("btn-caesar-rot13");
    const btnReset = document.getElementById("btn-caesar-reset");
    const btnCopy = document.getElementById("btn-copy-caesar");
    const modeRadios = document.querySelectorAll('input[name="caesar-mode"]');

    if (!slider || !input) return;

    function getSelectedMode() {
        let mode = "encrypt";
        modeRadios.forEach(r => { if (r.checked) mode = r.value; });
        return mode;
    }

    function updateShiftVisuals(s) {
        if (shiftVal) shiftVal.textContent = s;
        if (revShift) revShift.textContent = (26 - (s % 26)) % 26;
        if (shiftAlpha) {
            const shifted = [];
            for (let i = 0; i < 26; i++) {
                shifted.push(String.fromCharCode(((i + s) % 26) + 65));
            }
            shiftAlpha.textContent = shifted.join(" ");
        }
    }

    async function runCaesar() {
        const text = input.value;
        const shift = parseInt(slider.value, 10);
        const mode = getSelectedMode();

        updateShiftVisuals(shift);

        if (!text) {
            if (output) output.textContent = "";
            return;
        }

        try {
            const response = await fetch("/crypto-lab/api/caesar", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text, shift, mode })
            });
            const res = await response.json();
            if (res.success && output) {
                output.textContent = res.data.output_text;
            }
        } catch (err) {
            console.error("Caesar error:", err);
        }
    }

    slider.addEventListener("input", function () {
        updateShiftVisuals(parseInt(this.value, 10));
        runCaesar();
    });

    input.addEventListener("input", runCaesar);
    modeRadios.forEach(r => r.addEventListener("change", runCaesar));

    if (btnApply) btnApply.addEventListener("click", runCaesar);

    if (btnRot13) {
        btnRot13.addEventListener("click", function () {
            slider.value = 13;
            runCaesar();
        });
    }

    if (btnReset) {
        btnReset.addEventListener("click", function () {
            slider.value = 3;
            runCaesar();
        });
    }

    if (btnCopy && output) {
        btnCopy.addEventListener("click", function () {
            navigator.clipboard.writeText(output.textContent.trim()).then(() => {
                btnCopy.innerHTML = `<i class="bi bi-check-lg text-success"></i> Copied!`;
                setTimeout(() => {
                    btnCopy.innerHTML = `<i class="bi bi-clipboard"></i> Copy`;
                }, 2000);
            });
        });
    }

    // Initial run
    runCaesar();
}

/**
 * 3. RSA Public & Private Key Demonstration Handler
 */
function initRsaDemo() {
    const btnGen = document.getElementById("btn-rsa-generate");
    const pubKeyEl = document.getElementById("rsa-public-key");
    const privKeyEl = document.getElementById("rsa-private-key");
    const plainInput = document.getElementById("rsa-plaintext");
    const charCounter = document.getElementById("rsa-char-counter");
    const btnEncrypt = document.getElementById("btn-rsa-encrypt");
    const cipherContainer = document.getElementById("rsa-cipher-container");
    const cipherOutput = document.getElementById("rsa-ciphertext-output");
    const btnDecrypt = document.getElementById("btn-rsa-decrypt");
    const decResult = document.getElementById("rsa-dec-result");
    const decText = document.getElementById("rsa-dec-text");

    if (!plainInput) return;

    if (plainInput && charCounter) {
        plainInput.addEventListener("input", function () {
            const bytes = new TextEncoder().encode(plainInput.value).length;
            charCounter.textContent = bytes;
            if (bytes > 190) {
                charCounter.className = "text-danger fw-bold";
            } else {
                charCounter.className = "text-azure";
            }
        });
    }

    if (btnGen) {
        btnGen.addEventListener("click", async function () {
            btnGen.disabled = true;
            btnGen.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Generating 2048-bit RSA...`;

            try {
                const response = await fetch("/crypto-lab/api/rsa/generate-keys", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" }
                });
                const res = await response.json();
                if (res.success) {
                    if (pubKeyEl) pubKeyEl.value = res.data.public_key_pem;
                    if (privKeyEl) privKeyEl.value = res.data.private_key_pem;
                    if (cipherContainer) cipherContainer.classList.add("d-none");
                    if (decResult) decResult.classList.add("d-none");
                } else {
                    alert("Key generation error: " + (res.error || "Failed"));
                }
            } catch (err) {
                alert("Network error: " + err.message);
            } finally {
                btnGen.disabled = false;
                btnGen.innerHTML = `<i class="bi bi-arrow-clockwise me-1"></i> Generate New Key Pair`;
            }
        });
    }

    if (btnEncrypt) {
        btnEncrypt.addEventListener("click", async function () {
            const plaintext = plainInput.value.trim();
            const pubKey = pubKeyEl ? pubKeyEl.value.trim() : "";

            if (!plaintext) {
                alert("Please enter a short message to encrypt with RSA.");
                return;
            }
            if (!pubKey) {
                alert("Please generate or enter an RSA Public Key.");
                return;
            }

            btnEncrypt.disabled = true;
            btnEncrypt.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Encrypting with RSA...`;

            try {
                const response = await fetch("/crypto-lab/api/rsa/encrypt", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ public_key: pubKey, plaintext: plaintext })
                });
                const res = await response.json();
                if (res.success) {
                    if (cipherOutput) cipherOutput.value = res.data.ciphertext_b64;
                    if (cipherContainer) cipherContainer.classList.remove("d-none");
                    if (decResult) decResult.classList.add("d-none");
                } else {
                    alert("RSA Encryption Error: " + (res.error || "Failed"));
                }
            } catch (err) {
                alert("Network error: " + err.message);
            } finally {
                btnEncrypt.disabled = false;
                btnEncrypt.innerHTML = `<i class="bi bi-lock-fill me-1"></i> Encrypt with Public Key`;
            }
        });
    }

    if (btnDecrypt) {
        btnDecrypt.addEventListener("click", async function () {
            const privKey = privKeyEl ? privKeyEl.value.trim() : "";
            const ct = cipherOutput ? cipherOutput.value.trim() : "";

            if (!privKey || !ct) {
                alert("RSA Private Key and Ciphertext are required for decryption.");
                return;
            }

            btnDecrypt.disabled = true;
            btnDecrypt.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Decrypting with RSA...`;

            try {
                const response = await fetch("/crypto-lab/api/rsa/decrypt", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ private_key: privKey, ciphertext: ct })
                });
                const res = await response.json();
                if (res.success) {
                    if (decText) decText.textContent = res.data.decrypted_plaintext;
                    if (decResult) decResult.classList.remove("d-none");
                } else {
                    alert("RSA Decryption Error: " + (res.error || "Failed"));
                }
            } catch (err) {
                alert("Network error: " + err.message);
            } finally {
                btnDecrypt.disabled = false;
                btnDecrypt.innerHTML = `<i class="bi bi-unlock-fill me-1"></i> Decrypt with Matching Private Key`;
            }
        });
    }
}

/**
 * 4. SHA-256 One-Way Hash & Avalanche Effect Handler
 */
function initSha256Demo() {
    const singleInput = document.getElementById("sha-single-input");
    const btnCalcSha = document.getElementById("btn-calc-sha");
    const singleOutput = document.getElementById("sha-single-output");
    const btnCopySha = document.getElementById("btn-copy-sha");

    const avInput1 = document.getElementById("av-input-1");
    const avInput2 = document.getElementById("av-input-2");
    const btnTestAv = document.getElementById("btn-test-avalanche");
    const avHash1 = document.getElementById("av-hash-1");
    const avHash2 = document.getElementById("av-hash-2");
    const avBitDiff = document.getElementById("av-bit-diff");
    const avPctDiff = document.getElementById("av-pct-diff");
    const avStatus = document.getElementById("av-status");

    if (!singleInput) return;

    async function calcSingleHash() {
        const text = singleInput.value;
        if (!text) {
            if (singleOutput) singleOutput.textContent = "";
            return;
        }
        try {
            const response = await fetch("/crypto-lab/api/sha256", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text })
            });
            const res = await response.json();
            if (res.success && singleOutput) {
                singleOutput.textContent = res.data.hash_hex;
            }
        } catch (err) {
            console.error("SHA256 error:", err);
        }
    }

    if (btnCalcSha) btnCalcSha.addEventListener("click", calcSingleHash);
    singleInput.addEventListener("input", calcSingleHash);

    if (btnCopySha && singleOutput) {
        btnCopySha.addEventListener("click", function () {
            navigator.clipboard.writeText(singleOutput.textContent.trim()).then(() => {
                btnCopySha.innerHTML = `<i class="bi bi-check-lg text-success"></i> Copied!`;
                setTimeout(() => {
                    btnCopySha.innerHTML = `<i class="bi bi-clipboard"></i> Copy`;
                }, 2000);
            });
        });
    }

    async function calcAvalanche() {
        if (!avInput1 || !avInput2) return;
        const text1 = avInput1.value;
        const text2 = avInput2.value;

        try {
            const response = await fetch("/crypto-lab/api/sha256/avalanche", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text1, text2 })
            });
            const res = await response.json();
            if (res.success) {
                const d = res.data;
                if (avHash1) avHash1.textContent = d.input1.hash_hex;
                if (avHash2) avHash2.textContent = d.input2.hash_hex;
                if (avBitDiff) avBitDiff.textContent = `${d.bit_differences} / 256 bits`;
                if (avPctDiff) avPctDiff.textContent = `${d.bit_difference_pct}%`;
                if (avStatus) {
                    if (d.bit_difference_pct >= 40 && d.bit_difference_pct <= 60) {
                        avStatus.className = "badge bg-success p-2";
                        avStatus.textContent = "Optimal Avalanche (~50%)";
                    } else if (d.bit_difference_pct > 0) {
                        avStatus.className = "badge bg-info p-2";
                        avStatus.textContent = "Avalanche Demonstrated";
                    } else {
                        avStatus.className = "badge bg-secondary p-2";
                        avStatus.textContent = "Identical Inputs";
                    }
                }
            }
        } catch (err) {
            console.error("Avalanche error:", err);
        }
    }

    if (btnTestAv) btnTestAv.addEventListener("click", calcAvalanche);
    if (avInput1) avInput1.addEventListener("input", calcAvalanche);
    if (avInput2) avInput2.addEventListener("input", calcAvalanche);

    // Initial computations
    calcSingleHash();
    calcAvalanche();
}

