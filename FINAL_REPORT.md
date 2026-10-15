# SecureChat Final Project Report

**Project**: SecureChat (Zero-Trust End-to-End Encrypted Mobile Messaging)  
**Date**: 2026-10-15  
**Review Status**: PASSED (0 Critical, 0 High findings)  
**Artifacts Produced**: Android Debug APK (`app/build/app/outputs/flutter-apk/app-debug.apk`), FastAPI Relay Server, Complete Documentation & Verification Suite  

---

## 1. What Was Built

SecureChat is a complete, privacy-hardened mobile messaging application (Flutter client) and untrusted relay server (FastAPI + SQLite) engineered for zero-plaintext confidentiality and cryptographic non-repudiation.

### Core Cryptographic & Architectural Components:
1. **End-to-End Encryption**: AES-256-GCM symmetric authenticated encryption with fresh 96-bit CSPRNG nonces per message. Ephemeral symmetric keys wrapped with RSA-2048 OAEP-SHA256. Digital envelope signatures via Ed25519.
2. **Untrusted Relay Server**: Ephemeral relay using WebSockets and HTTP. Messages stored solely as opaque Base64 ciphertexts in SQLite and permanently purged from the database immediately upon delivery acknowledgement (`ack`). Zero private keys or session keys ever touch the server.
3. **Passwordless Challenge-Response Authentication**: Device key generation with ECDSA P-256 signatures over cryptographic nonces. Rotating single-use refresh tokens with automatic token family revocation upon reuse.
4. **Invite-Only Registration & Device Approval**: Multi-factor authentication via TOTP, 10 hashed single-use recovery codes, and new-device approval via QR code signing.
5. **Anti-Tamper & Brute-Force Defense**: Argon2id-derived 6-digit PIN ($m=4\text{MB}, t=2, p=1$), exponential progressive delays (5s to 300s), 10-failure emergency secure wipe (`deleteAll`), and 60-second background auto-lock.
6. **Platform Hardening**: Android `FLAG_SECURE` screen capture prevention, `allowBackup="false"`, `cleartextTrafficPermitted="false"`, iOS app switcher `UIBlurEffect`, iCloud backup exclusion, and generic lock-screen notifications.
7. **Certificate Pinning**: Enforced primary and backup SHA-256 certificate pinning with a documented zero-downtime rotation protocol.

---

## 2. Exact Commands to Run and Build

### Start the Backend Relay Server:
```bash
# Navigate to server directory and launch FastAPI
cd server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Generate a One-Time Registration Invite:
```bash
python server/manage.py create-invite --expires-hours 24
```

### Run the Server Verification Suite:
```bash
cd server
python -m pytest -v
```

### Run the Mobile App Test Suite:
```bash
cd app
flutter test
```

### Run the Mobile App Code Analyzer:
```bash
cd app
flutter analyze
```

### Build the Android Debug APK:
```bash
cd app
flutter build apk --debug
```
*Output Artifact*: `app/build/app/outputs/flutter-apk/app-debug.apk` (Size: 180,087,843 bytes).

---

## 3. VERIFIED (Executed & Confirmed in CI/Test Environment)

Every test below was actively executed in this environment with exact command outputs verified:

| Requirement / Component | Verification Command | Real Result |
| :--- | :--- | :--- |
| **Server Auth & Relay Suite (T01–T07)** | `python -m pytest -v` (in `server/`) | **PASS**: 27 passed in 9.59s. Validated challenge-response, nonce expiry, replay rejection, refresh token rotation, token reuse family revocation, TOTP enrollment/verification, single-use recovery code reuse prevention, device approval QR signing, privacy headers, rate limiting, and delete-on-ack delivery. |
| **App Crypto Suite (T08–T10)** | `flutter test test/crypto` (in `app/`) | **PASS**: 18 passed. AES-256-GCM authenticated encryption, KAT vectors, bit-tampering detection, 10,000 unique CSPRNG nonces, RSA-2048 isolate key generation, OAEP-SHA256 probabilistic wrapping, Ed25519 signature/verification, and envelope replay guards. |
| **Cross-Language Crypto Check (T12)** | `python tools/xcheck.py` | **PASS**: Bidirectional verification succeeded. Python decrypted 3 Dart-generated vectors; Dart decrypted 3 Python-generated vectors (including large 2KB payloads and multi-byte UTF-8 emojis). |
| **Key Storage & Safety Numbers (T11)** | `flutter test test/crypto/keystore_test.dart` | **PASS**: `KeyStore` abstraction over secure storage verified; 60-digit symmetric safety numbers and QR payloads verified identical on both endpoints. |
| **App Lock & Anti-Tamper (T14)** | `flutter test test/auth/app_lock_test.dart` | **PASS**: Argon2id 6-digit PIN derivation, exponential lockout delays (5s to 300s), 10-failure automatic keystore wipe, 60s background auto-lock, and biometric unlock. |
| **TOTP & Multi-Device UI (T15)** | `flutter test test/auth/totp_screens_test.dart` | **PASS**: QR code display, TOTP code confirmation, one-time recovery code display, and ECDSA new-device approval signing. |
| **Encrypted Local Storage (T16)** | `flutter test test/storage/storage_test.dart` | **PASS**: Per-record AES-256-GCM database encryption; zero plaintext markers on disk; tampering detection. |
| **Contacts & MITM Alert (T17)** | `flutter test test/contacts/contacts_test.dart` | **PASS**: QR contact card importing, safety number verification toggle, and prominent MITM alert on contact identity key change. |
| **Chat Service & WebSocket (T18)** | `flutter test test/chat/chat_service_test.dart` | **PASS**: WebSocket connection with exponential backoff, send=seal, receive=verify/open/store/ack, and offline queue flushing. |
| **Material 3 Chat UI (T19)** | `flutter test test/ui/chat_ui_test.dart` | **PASS**: 65 widget tests clean. Renders contact list, conversation thread with message status (Sending, Sent, Delivered), lock screen PIN keypad, and registration onboarding. |
| **Platform Privacy Flags (T20)** | `python tools/check_platform_flags.py` | **PASS**: All 6 flags verified: Android `allowBackup=false`, cleartext disabled, `FLAG_SECURE`, iOS backup exclusion, iOS `UIBlurEffect`, generic notifications. |
| **Certificate Pinning (T21)** | `flutter test test/network/cert_pinning_test.dart` | **PASS**: Primary SHA-256 pin match, backup pin fallback match, and mismatched pin rejection. |
| **Static & Crypto Linting (T22)** | `python tools/crypto_lint.py` | **PASS**: 0 crypto anti-patterns in repository; caught all 7 bad samples in self-test. |
| **Secret Scanning (T22)** | `python tools/scan_secrets.py` | **PASS**: 0 committed keys, tokens, or `.env` files; detected bad samples in self-test. |
| **SAST & Vulnerability Scans (T22)** | `python -m bandit -r server -lll`<br>`python -m pip_audit` | **PASS**: Bandit: 0 Medium / 0 High issues.<br>Pip-audit: 0 known vulnerabilities. |
| **Full End-to-End System Test (T23)** | `python tools/e2e.py` | **PASS**: Live test server launched on dynamic port. Two headless Flutter clients registered with invites, logged in via challenge-response, exchanged E2EE message over WebSocket, verified receipt and decryption, confirmed message purged upon ack, and verified zero plaintext in SQLite database and server logs. |
| **Android APK Build (T24)** | `flutter build apk --debug` | **PASS**: Compiled debug APK `app/build/app/outputs/flutter-apk/app-debug.apk` (180,087,843 bytes). |
| **iOS Configuration (T25)** | `python -c "import yaml; yaml.safe_load(open('codemagic.yaml'))"` | **PASS**: Codemagic CI unsigned IPA build specification validated cleanly. |
| **Documentation & Re-execution (T26)** | Two README commands re-run | **PASS**: `python server/manage.py create-invite` and `python tools/check_platform_flags.py` re-executed cleanly with exit code 0. |

---

## 4. NOT VERIFIED (Requires Physical Phone or macOS Hardware)

Per project guidelines, features requiring real mobile hardware or an Apple macOS build environment are compiled and statically verified, but not physically tested in CI:
- **Physical Secure Element / StrongBox**: Android Keystore hardware-backed keys (`HardwareDeviceKey`) and Apple Secure Enclave (`kSecAttrTokenIDSecureEnclave`).
- **Physical Biometric Sensors**: Hardware fingerprint scanner and FaceID sensor prompts (`local_auth`).
- **OS Screenshot Blocking**: Physical validation that Android Power + Volume Down displays *"Can't take screenshot due to security policy"*.
- **Physical iOS App Switcher Blur**: Visual confirmation of `UIBlurEffect` obscuring app window in iOS multitasking switcher.
- **Physical Push Notifications**: Apple APNs and Google FCM wake-up notifications on a cellular network.
- **iOS Sideloading Execution**: Physical signing via personal Apple ID (AltStore/Sideloadly) or TestFlight on a physical iPhone.
*Refer to [MANUAL_CHECKS.md](file:///c:/code12/MANUAL_CHECKS.md) for step-by-step physical phone verification procedures.*

---

## 5. Known Limitations & Threat Boundaries

1. **Traffic Metadata**: The relay server observes metadata (sender user ID, recipient user ID, message timestamp, ciphertext payload size, and client IP addresses). End-to-end encryption guarantees zero message plaintext is exposed, but communication graph metadata is visible to the network operator. Users desiring traffic analysis defense should route connections through a VPN or Tor.
2. **Unlocked Physical Device Seizure**: If an adversary seizes an unlocked, actively foregrounded phone, content on screen is readable. The 60-second background auto-lock and manual lock mitigate this once focus is lost.
3. **OS-Level Root / Jailbreak Compromise**: Advanced kernel-level spyware with root access can inspect memory or hook rendering pipelines. StrongBox and Secure Enclave key isolation mitigate private key extraction on supported devices.
4. **Independent Third-Party Audit**: This codebase has undergone automated cryptographic linter checks, secret scanning, bandit analysis, and cross-language vector verification, but has not yet undergone formal verification by an external commercial security audit firm.

---

## 6. Estimated Infrastructure & Deployment Costs

- **Relay Server VPS**: ~$4.00 – $6.00/month (Hetzner, DigitalOcean, or Linode 1 vCPU, 1 GB RAM, Ubuntu 24.04).
- **Domain Name**: ~$10.00 – $12.00/year (`.com` or `.net` via Cloudflare Registrar or Namecheap).
- **SSL/TLS Certificates**: $0.00 (Automated TLS 1.3 certificates via Let's Encrypt and Caddy).
- **Apple Developer Account (Optional)**:
  - Free Apple ID: $0.00 (Sideload via AltStore / Sideloadly; 7-day profile renewal required; 3-app limit; no APNs).
  - Paid Apple Developer Program: $99.00/year (1-year profile; TestFlight; APNs push notifications).
