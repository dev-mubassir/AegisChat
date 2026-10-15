# SecureChat Context & Handoff

## Environment & Tool Versions
- OS: Windows (win32, x64)
- Python: 3.14.7 | Git: 2.55.0.windows.3
- Flutter: 3.47.7 (channel stable) | Dart: 3.13.5
- Pytest: 9.1.1 | Ruff: 0.17.0 | FastAPI: 0.143.1 | Cryptography: 50.0.2

## Commands That Work
- S: `cd server && python -m pytest -q`
- Ruff: `python -m ruff check server`
- A: `cd app && C:\src\flutter\bin\flutter.bat analyze && C:\src\flutter\bin\flutter.bat test`
- Crypto tests: `cd app && C:\src\flutter\bin\flutter.bat test test/crypto`

- XCheck: `python tools/xcheck.py`

## Decisions
- Protocol v1 envelope: 0x01 version, sender/recipient/msg ID, timestamp, RSA-2048 OAEP wrapped AES key, AES-256-GCM ciphertext + MAC, Ed25519 signature.
- Strict checks: recipient verification, 300s clock skew window, replay guard cache, signature verification.
- Documented in `docs/PROTOCOL.md`.
- Verified bidirectional compatibility between Dart PointyCastle/cryptography and Python cryptography.
- DeviceKey interface: HardwareDeviceKey compile-checked with MethodChannel, SoftwareDeviceKey for tests only (throws if used in release mode). Manual checks documented in MANUAL_CHECKS.md.
- TOTP & Approval: TotpService with canonical payload signing matching Python server, TotpEnrollmentScreen & DeviceApprovalScreen.

- Contacts & Verification: ContactManager with QR contact cards, 60-digit symmetric safety numbers, verified badges, and automatic key change detection/warnings.

## What Is Next
- T20: Platform privacy flags (Android allowBackup=false, network security config, FLAG_SECURE on MainActivity, generic notification text; tools/check_platform_flags.py).

## Attempt Log
- T01..T07: PASS (Server skeleton, Flutter skeleton, DB, Auth, Relay, Privacy, TOTP/Approval).
- T08..T12: PASS (AES-256-GCM, RSA-OAEP/Ed25519, Message Envelope, KeyStore/Safety, Cross-check).
- T13: PASS. DeviceKey abstraction, SoftwareDeviceKey, LoginClient challenge/response, refresh rotation.
- T14: PASS. AppLockManager with Argon2id PIN, biometrics, delays, 10-failure wipe, 60s auto-lock.
- T15: PASS. TOTP enrolment, recovery codes, new-device approval QR and widget tests.
- T16: PASS. EncryptedMessageStore with per-record AES-256-GCM, zero plaintext on disk, wrong key rejection.
- T17: PASS. ContactManager, safety numbers, verified flag, key change alert UI and tests.
- T18: PASS. ChatService WebSocket client, reconnect/backoff, send/seal, receive/open/ack, offline queue.
- T19: PASS. Chat UI (Material 3 contacts screen, chat conversation screen, registration/invite screen, lock screen with PIN/biometrics, safety number screen, widget tests).
