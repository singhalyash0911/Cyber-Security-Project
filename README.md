# SecureStego 🛡️
### Image-Based Secret Message Hiding Using Steganography and Authenticated Encryption
**MCA 3rd-Semester Cyber Security Academic Project**

---

## 1. Project Overview & Objectives

**SecureStego** is a cybersecurity web application developed as an academic project for MCA (Master of Computer Applications) 3rd semester. The goal of this project is to demonstrate **defense-in-depth** by combining two foundational cybersecurity principles:

1. **Steganography (Concealing Existence):** Hiding confidential text inside ordinary PNG image files by subtly modifying the least significant bits (LSB) of RGB pixel channels without producing visual distortion.
2. **Authenticated Encryption (Protecting Confidentiality & Integrity):** Encrypting the secret text using **AES-256-GCM** with a key derived via **PBKDF2-HMAC-SHA256**. Even if a third party suspects that data is hidden in the carrier image, they cannot read, decrypt, or alter the payload without knowing the secret password.

---

## 2. Key Features

- **Authenticated Encryption (AES-256-GCM):** Guarantees confidentiality and provides built-in integrity verification via a 128-bit authentication tag.
- **Robust Key Derivation (PBKDF2-HMAC-SHA256):** Stretches passwords over 100,000 iterations with a unique, cryptographically random 16-byte salt per message to thwart rainbow table attacks.
- **Fresh Nonce Generation:** Employs a fresh 12-byte random nonce (`os.urandom(12)`) for every encryption to prevent pattern leakage.
- **LSB Image Steganography:** Lossless spatial-domain embedding into the Red, Green, and Blue color channels of PNG images while preserving image dimensions and alpha channel transparency.
- **Magic Header & Length Verification:** 4-byte signature `b"SSTE"` and a 32-bit length prefix prevent parsing ordinary or corrupted images.
- **In-Memory Zero-Persistence Processing:** Secret messages and passwords are processed in memory and never stored in a database or on disk.
- **Interactive UI & Capacity Estimator:** Real-time client-side calculation of available image capacity and character counter as users type.
- **One-Click Download & Clipboard Copy:** Direct download of generated stego PNG files and convenient copy-to-clipboard for revealed messages.
- **Safe HTML Rendering:** Jinja2 auto-escaping and sanitized output prevent cross-site scripting (XSS).

---

## 3. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Backend Framework** | Python 3.11+ / Flask | Web routing, form validation, and controller logic |
| **Cryptography** | `cryptography` (PyCA) | AES-256-GCM, PBKDF2HMAC, SHA-256, secure random byte generation |
| **Image Processing** | Pillow (`PIL`) | PNG validation, pixel manipulation, LSB bit modification |
| **Frontend Layout** | HTML5, Bootstrap 5.3, Bootstrap Icons | Responsive cybersecurity dark-themed layout |
| **Custom Styling** | Vanilla CSS (`style.css`) | Dark navy palette (`#070b19`), azure accent (`#38bdf8`), glowing cards |
| **Client Logic** | Vanilla JavaScript (`main.js`) | Instant image preview, live capacity calculator, password toggles |
| **Automated Testing** | `pytest` | 30 comprehensive unit and integration tests |

---

## 4. End-to-End Workflow Diagram

```
[ Secret Message ] (Plaintext)
       │
       ▼
[ PBKDF2-HMAC-SHA256 ] ── (100,000 Iterations + 16-byte Salt) ──► 256-bit Key
       │
       ▼
[ AES-256-GCM Encryption ] ── (12-byte Nonce) ──► Ciphertext + 16-byte Tag
       │
       ▼
[ Payload Assembly ] ── [ Salt (16B) | Nonce (12B) | Ciphertext + Tag (N+16B) ]
       │
       ▼
[ Stego Header Pack ] ── [ 'SSTE' (4B) | Payload Length (4B) | Encrypted Payload ]
       │
       ▼
[ LSB RGB Embedding ] ── Modifies LSB of pixels in Carrier PNG image
       │
       ▼
[ Output Carrier PNG ] ── Indistinguishable to human eye from original image
       │
       ▼  (Transmission / Storage)
       │
[ LSB Bit Extraction ] ── Reads 'SSTE' magic header, payload length, and bits
       │
       ▼
[ Key Derivation & AES-GCM Verification ]
       ├── If password is correct and tag valid  ──► [ Original Plaintext ]
       └── If password is wrong or bits tampered ──► [ DecryptionError: Authentication Failed ]
```

---

## 5. Project Directory Structure

```
Cyber Security Project/
├── app.py                     # Main Flask web application and routing
├── encryption.py              # AES-256-GCM and PBKDF2 key derivation module
├── crypto_lab.py              # Educational Crypto Lab module (AES, Caesar, RSA, SHA-256)
├── steganography.py           # Pillow-based LSB embedding & extraction module
├── requirements.txt           # Python dependencies
├── sample_carrier.png         # Ready-to-use sample PNG image for testing
├── README.md                  # Comprehensive documentation and viva guide
├── static/
│   ├── css/
│   │   └── style.css          # Dark navy & blue cybersecurity theme
│   └── js/
│       └── main.js            # Image previews, live capacity gauge, Crypto Lab client
├── templates/
│   ├── base.html              # Base layout with navbar, alerts, and footer
│   ├── index.html             # Page 1: Home landing page
│   ├── hide.html              # Page 2: Hide message form & download card
│   ├── reveal.html            # Page 3: Reveal message form & result display
│   ├── crypto_lab.html        # Page 5: Educational Crypto Lab (MCA Syllabus)
│   └── about.html             # Page 4: Technical architecture & viva guide
└── tests/
    ├── __init__.py
    ├── test_encryption.py     # 10 encryption & key derivation tests
    ├── test_steganography.py  # 8 LSB steganography & capacity tests
    ├── test_crypto_lab.py     # 20 Crypto Lab unit, algorithm & API tests
    └── test_app.py            # 12 Flask routes, validation, and HTTP workflow tests
```

---

## 6. Installation & Quickstart

### Prerequisites
- Python 3.10+ installed on your system.

### Step 1: Clone or Navigate to the Project Directory
```bash
cd "d:\Cyber Security Project"
```

### Step 2: (Optional but Recommended) Create a Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Automated Test Suite
Ensure all cryptographic, steganographic, and Crypto Lab modules are passing:
```bash
pytest tests/
```
*(All 50 unit, integration, and API tests should pass in under 4 seconds).*

### Step 5: Start the Flask Application
```bash
python app.py
```

### Step 6: Open the Website in Your Browser
Open your preferred web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 7. How to Test the Application

### A. Core Steganography Workflow (Primary Focus)

1. **Hide a Secret Message (`/hide`):**
   - Click **"Hide a Message"** from the home page.
   - Click **"Select Carrier PNG Image"** and choose the provided `sample_carrier.png` (or any PNG from your computer).
   - Notice the live preview showing image dimensions and calculated capacity!
   - In **Secret Message**, type: `Top secret credentials for MCA Viva 2026!`.
   - In **Encryption Password**, enter: `SecretPass@123`.
   - In **Confirm Password**, enter: `SecretPass@123`.
   - Click **"Hide and Download"**.
   - A success card will display the resulting stego image preview, payload metrics, and a **"Download Stego Image (PNG)"** button. Click to save `stego_sample_carrier.png`.

2. **Reveal the Secret Message (`/reveal`):**
   - Click **"Reveal Message"** in the top navigation bar.
   - Upload the downloaded `stego_sample_carrier.png`.
   - Enter the password: `SecretPass@123`.
   - Click **"Reveal Message"**.
   - The message is authenticated via AES-GCM and displayed cleanly in the read-only box with a **"Copy Message"** button!

3. **Test Security & Integrity Rejection:**
   - On the **Reveal** page, upload the same stego image but enter a wrong password (e.g. `WrongPass!`).
   - Click **"Reveal Message"**.
   - Notice the clean, secure error message: *"Authentication failed: Incorrect password or corrupted payload."*

---

### B. Educational Crypto Lab Demonstrations (`/crypto-lab`)

Click the **Crypto Lab** navigation tab to explore interactive demonstrations for the MCA Cyber Security and Cryptography syllabus:

1. **AES-256-GCM (Symmetric Encryption):**
   - Reuses the project's core [`encryption.py`](file:///d:/Cyber%20Security%20Project/encryption.py) module.
   - Enter plaintext and password, then click **"Encrypt with AES-256-GCM"**.
   - Inspect the granular breakdown: 16-byte random salt, PBKDF2 derived 256-bit key, 12-byte nonce, ciphertext, and 16-byte authentication tag.
   - Test authenticated decryption, and click **"Tamper"** to flip a bit and witness the GCM authentication tag actively detect corruption and reject decryption!

2. **Caesar Cipher (Classical Substitution):**
   - Enter text and slide the shift value $k$ from 1 to 25.
   - See the real-time alphabet substitution mapping ($A \to D, B \to E, \dots$).
   - Switch between Encrypt and Decrypt modes, or click **"Set ROT13"**.
   - Includes a clear educational disclaimer explaining why Caesar ciphers are strictly academic and insecure (only 25 keys, vulnerable to frequency analysis).

3. **RSA Public & Private Key Encryption (Asymmetric):**
   - Uses the Python `cryptography` library with modern **OAEP (SHA-256)** padding.
   - Generates a fresh temporary 2048-bit demonstration key pair.
   - Displays the public key (role: encryption) and private key (role: decryption).
   - Enter a short message (max 190 bytes for RSA-2048 with OAEP-SHA256) and encrypt with the public key.
   - Decrypt with the private key to recover the message.
   - Explains why RSA is used for key exchange or hybrid encryption rather than bulk steganography payloads.

4. **SHA-256 One-Way Hash Function & Avalanche Effect:**
   - Calculate fixed 256-bit (64 hex characters) cryptographic hash digests.
   - Demonstrates the **Avalanche Effect** with side-by-side inputs (e.g., `CyberSecurity2026` vs `CyberSecurity2027`), displaying the Hamming bit difference and verifying that ~50% of bits flip when a single character changes.
   - Highlights the fundamental rule: hashing is strictly one-way and is not encryption or safe plain password protection.

5. **MCA Syllabus Theory Reference:**
   - Concise academic review cards covering:
     - **Transposition Ciphers** (Rail Fence, Columnar Transposition vs Substitution)
     - **Block vs. Stream Ciphers** (Block sizes, modes: ECB, CBC, GCM vs keystream ciphers like ChaCha20)
     - **DES Limitations** (56-bit keys, brute-force feasibility, 3DES, transition to AES)
     - **Key Management** (Generation, Distribution, Storage, Rotation, Destruction, Kerckhoffs's Principle)
     - **Diffie–Hellman Key Exchange** (Discrete log problem, establishing shared secrets over untrusted channels)
     - **Digital Signatures** (Hash + private key signing, public key verification, non-repudiation)

---

## 8. Cryptographic Specifications

- **Algorithm:** AES-256 in Galois/Counter Mode (GCM).
- **Key Size:** 256 bits (32 bytes).
- **Key Derivation Function:** PBKDF2 with HMAC-SHA256.
- **Iterations:** 100,000 rounds (OWASP recommended standard for desktop/web key stretching).
- **Salt:** 16 cryptographically secure random bytes generated via `os.urandom(16)`.
- **Nonce (IV):** 12 cryptographically secure random bytes generated via `os.urandom(12)`.
- **Authentication Tag:** 16 bytes (128 bits) appended to the ciphertext.
- **Payload Structure:**
  ```
  [ Salt: 16 Bytes ] [ Nonce: 12 Bytes ] [ Ciphertext: N Bytes ] [ Tag: 16 Bytes ]
  ```
- **Total Overhead:** 44 bytes + plaintext length.

---

## 9. LSB Steganography Specifications

- **Carrier Format:** PNG (Portable Network Graphics) — lossless compression is mandatory.
- **Target Channels:** Red, Green, and Blue color channels (bit 0 of each channel byte).
- **Alpha Channel:** Left completely untouched if present (RGBA) to prevent transparency artifacts.
- **Header Structure:**
  ```
  [ Magic Signature: 4 Bytes ("SSTE") ] [ Payload Length: 4 Bytes (Big-Endian uint32) ]
  ```
- **Theoretical Capacity Formula:**
  $$\text{Max Payload Bytes} = \left\lfloor \frac{\text{Width} \times \text{Height} \times 3}{8} \right\rfloor - 8$$
  *(For a $600 \times 400$ image, capacity is approximately $89,992$ bytes / $\sim 87.8$ KB).*

---

## 10. Known Limitations & Security Considerations

1. **Lossy Compression Destroys Stego Data:** If a stego PNG image is converted to JPEG, WebP (lossy), or sent through image-optimizing chat applications (like standard WhatsApp compression), the high-frequency LSB changes will be discarded during discrete cosine transform (DCT) quantization.
2. **Geometric Transformations:** Resizing, cropping, rotating, or applying Instagram-style color filters will recalculate pixel values through interpolation, corrupting the hidden bits.
3. **Steganalysis:** Statistical testing (such as Chi-Square analysis or Sample Pair Analysis) can detect unnatural bit distributions in LSB planes. However, because SecureStego encrypts the payload with AES-256-GCM before embedding, an analyst can only suspect the presence of data; they can never read the contents without the password.

---

## 11. Student Viva Guide & Work Division

This project is tailored for a team of **three MCA students**:

### Student 1: Security & Cryptography Specialist
- **Primary Module:** [`encryption.py`](file:///d:/Cyber%20Security%20Project/encryption.py)
- **Topics to Explain:**
  - What is AES-256-GCM and why is it preferred over AES-CBC? *(GCM is an AEAD cipher that provides both encryption and built-in message authentication via a Galois hash tag).*
  - Why is PBKDF2 used instead of hashing the password directly with SHA-256? *(Passphrases have low entropy; PBKDF2 performs 100,000 iterations to resist GPU/ASIC brute-force cracking).*
  - Why do we need a random salt and nonce? *(The salt stops precomputed rainbow tables; the nonce ensures encrypting the same text twice yields different ciphertexts).*

### Student 2: Image Processing & Steganography Engine Specialist
- **Primary Module:** [`steganography.py`](file:///d:/Cyber%20Security%20Project/steganography.py)
- **Topics to Explain:**
  - How does Least Significant Bit (LSB) embedding work at the byte level? *(Bitwise AND with `~1` to clear bit 0, then bitwise OR with the message bit).*
  - Why only PNG and not JPEG? *(JPEG uses lossy DCT compression which alters pixel values upon saving, corrupting the LSB bits).*
  - How does the application identify valid hidden data? *(It checks the 4-byte magic signature `b"SSTE"` and reads the 32-bit length header).*
  - How is image capacity calculated? *(Each pixel has 3 RGB channels; each channel stores 1 bit; capacity is $(W \times H \times 3) / 8 - 8$ bytes).*

### Student 3: Web Architecture & Full-Stack Integration Specialist
- **Primary Modules:** [`app.py`](file:///d:/Cyber%20Security%20Project/app.py), [`templates/`](file:///d:/Cyber%20Security%20Project/templates/), [`static/`](file:///d:/Cyber%20Security%20Project/static/)
- **Topics to Explain:**
  - How does the web application avoid saving files on disk? *(Uses Python `io.BytesIO` in-memory buffers and returns base64 data URLs for client-side download).*
  - How are file uploads secured? *(File extension checking, MIME validation, and Pillow `Image.open` format verification with a 16 MB size limit).*
  - How does the frontend estimate capacity in real time? *(Client JavaScript reads image natural dimensions via `Image()` object and updates the counter as the user types).*
