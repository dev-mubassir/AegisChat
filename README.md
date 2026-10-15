# SecureChat: Zero-Trust End-to-End Encrypted Mobile Messaging

SecureChat is a modern, privacy-focused end-to-end encrypted (E2EE) messaging system engineered to provide provable, zero-plaintext confidentiality and cryptographic non-repudiation between mobile devices across an untrusted relay server.

---

## Architecture & Cryptographic Guarantees

- **Message Confidentiality & Authenticity**: AES-256-GCM authenticated encryption with a fresh CSPRNG 96-bit nonce per message. Associated Authenticated Data (AAD) binds sender, recipient, message ID, and timestamp.
- **Key Encapsulation**: Ephemeral symmetric keys encapsulated via RSA-2048 with OAEP-SHA256 padding.
- **Digital Signatures**: Ed25519 cryptographic signatures over every envelope.
- **Zero Plaintext Storage**: The relay server stores only opaque Base64-encoded encrypted blobs. Messages are permanently deleted upon receipt of delivery acknowledgement (`ack`).
- **Encrypted Local Storage**: Local SQLite message store encrypted at rest per-record using AES-256-GCM with keys isolated in the platform secure enclave / hardware keystore.
- **Hardware Isolation**: `FLAG_SECURE` prevents Android screenshots and recent app switcher leaks; iOS app switcher uses `UIBlurEffect`; ADB backups disabled (`allowBackup="false"`).
- **Anti-Tamper & Brute-Force Defense**: Argon2id-derived 6-digit PIN with progressive exponential delays and an automatic 10-failure emergency key wipe. 60-second background auto-lock.

---

## 1. Prerequisites

- **Python**: 3.10+ (with `venv` and `pip`)
- **Flutter**: 3.47+ (Dart 3.13+)
- **Java**: OpenJDK 17 LTS
- **Android SDK**: API Level 34+ / Build-Tools 36.0.0+

---

## 2. Server Setup & Execution

### Install Server Dependencies
```bash
cd server
pip install -r requirements.txt
```

### Initialize Database & Start Relay Server
Run the FastAPI server on localhost or across your local network:
```bash
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
```
API docs are available at `http://localhost:8000/docs`.

### Generate Registration Invite Code
User registration is strictly invite-gated. Generate a one-time 24-hour invite:
```bash
python server/manage.py create-invite --expires-hours 24
```
Output:
```
GLS5ElXtRQHEYFVjf_dESUs9x-rM8gH7
```

---

## 3. Running the Test Suite

### Server Unit & Integration Tests
Runs challenge-response auth, refresh rotation, TOTP enrollment, device approvals, and relay tests:
```bash
cd server && python -m pytest -v
```

### Flutter Unit, Crypto & Widget Tests
Runs 65+ unit, widget, and platform tests:
```bash
cd app && flutter test
```

### Flutter Code Analyzer
Enforces clean Dart code with zero lint warnings:
```bash
cd app && flutter analyze
```

### Static Analysis, Cryptographic Linter & Secret Scanner
```bash
python tools/crypto_lint.py
python tools/scan_secrets.py
python tools/check_platform_flags.py
bandit -r server -lll
pip-audit
```

### Cross-Language Verification Test
Verifies that message envelopes sealed in Dart can be opened in Python, and vice versa:
```bash
python tools/xcheck.py
```

### Full End-to-End Headless Integration Test
Launches a test server instance and runs headless Flutter clients exchanging E2EE messages:
```bash
python tools/e2e.py
```

---

## 4. Building the Android APK

Build a debug APK for development or testing:
```bash
cd app
flutter build apk --debug
```
The compiled package is located at:
```
app/build/app/outputs/flutter-apk/app-debug.apk
```

---

## 5. Installing and Running on a Physical Phone

### Method A: Install via ADB (USB Debugging)
1. Enable **Developer Options** and **USB Debugging** on your Android device.
2. Connect your phone to your PC via USB cable.
3. Install the APK:
   ```bash
   adb install -r app/build/app/outputs/flutter-apk/app-debug.apk
   ```

### Method B: Sideload via Direct Transfer
1. Copy `app-debug.apk` to your phone via USB file transfer, Google Drive, or local file server.
2. In your phone's file manager, tap `app-debug.apk`.
3. If prompted, allow "Install unknown apps" for your file manager.
4. Tap **Install** and launch **SecureChat**.

---

## 6. Production Deployment with Caddy & HTTPS Domain

SecureChat relies on TLS 1.3 with SHA-256 certificate pinning. Use Caddy to obtain free, automatic Let's Encrypt certificates.

### `Caddyfile`
```caddy
chat.yourdomain.com {
    reverse_proxy 127.0.0.1:8000

    # Strict HTTPS and Privacy Headers
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "no-referrer"
    }

    # Enable WebSocket compression & buffering bypass
    @websockets {
        header Connection *Upgrade*
        header Upgrade websocket
    }
    reverse_proxy @websockets 127.0.0.1:8000
}
```

### Extract SHA-256 Certificate Pin
After issuing the certificate with Caddy, extract the public key pin:
```bash
openssl x509 -in /etc/caddy/certificates/acme-v02.api.letsencrypt.org-directory/chat.yourdomain.com/chat.yourdomain.com.crt -outform der | openssl dgst -sha256 -binary | openssl base64
```
Insert the pin into `app/lib/network/cert_pinning.dart` under `primaryPin`. See `docs/SECURITY.md` for certificate rotation instructions.
