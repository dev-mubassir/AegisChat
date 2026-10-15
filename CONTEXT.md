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
- App lock: Argon2id 6-digit PIN derivation, 5s-300s progressive lockout delays, 10-failure automatic key wiping, and 60s background auto-lock.

## What Is Next
- T15: TOTP, recovery and new-device screens (TOTP enrolment, single-use recovery codes, new-device approval QR).

## Attempt Log
- T01..T07: PASS (Server skeleton, Flutter skeleton, DB, Auth, Relay, Privacy, TOTP/Approval).
- T08: PASS. AES-256-GCM authenticated encryption.
- T09: PASS. RSA-2048 OAEP key wrap/unwrap, Ed25519 sign & verify.
- T10: PASS. Message envelope seal() and open(), replay guard, clock skew, protocol spec.
- T11: PASS. KeyStore abstraction & in-memory fake, 60-digit symmetric safety number, QR verification payload.
- T12: PASS. Bidirectional cross-language crypto checks (Dart <-> Python reference implementation).
- T13: PASS. DeviceKey abstraction, SoftwareDeviceKey ECDSA P-256, LoginClient challenge/response, refresh rotation.
- T14: PASS. AppLockManager with Argon2id PIN, biometrics, delays, 10-failure wipe, 60s background auto-lock.
