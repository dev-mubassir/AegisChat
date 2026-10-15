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
- AES-256-GCM implemented via `package:cryptography` with 96-bit random nonces.
- Flip-any-bit tamper tests and 10,000 nonces uniqueness verified.
- EncryptedPayload serialization format: 12-byte nonce + 16-byte MAC + ciphertext.

## What Is Next
- T09: RSA-OAEP and signatures (RSA-2048 keygen in isolate, OAEP-SHA256 32-byte key wrapping, Ed25519 signing).

## Attempt Log
- T01..T07: PASS (Server skeleton, Flutter skeleton, DB, Auth, Relay, Privacy, TOTP/Approval).
- T08: PASS. AES-256-GCM encryption/decryption, KAT vectors, bit tampering, 10k nonce uniqueness.
