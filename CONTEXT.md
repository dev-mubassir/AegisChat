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

## Decisions
- RSA-2048 key generation runs in background worker isolate (`Isolate.run`).
- Key wrapping uses OAEP with SHA-256 digest and randomized Fortuna padding for 32-byte AES key.
- Digital signatures use Ed25519 (64-byte signatures, 32-byte public keys).

## What Is Next
- T10: Message envelope (`seal()` and `open()`, docs/PROTOCOL.md, associated data, replay guard, clock skew).

## Attempt Log
- T01..T07: PASS (Server skeleton, Flutter skeleton, DB, Auth, Relay, Privacy, TOTP/Approval).
- T08: PASS. AES-256-GCM encryption/decryption, KAT vectors, 10k unique nonces.
- T09: PASS. RSA-2048 OAEP key wrap/unwrap, Isolate keygen, Ed25519 sign & verify.
