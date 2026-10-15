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
- CLI Invite: `python server/manage.py create-invite`

## Decisions
- TOTP enrolment using pyotp with 10 single-use recovery codes hashed with Argon2id.
- New-device approval: old device verifies TOTP and signs new device public keys.
- Unknown devices and wrong TOTP/recovery codes are rejected.

## What Is Next
- T08: App crypto - AES-256-GCM (app/lib/crypto/aes_gcm.dart, 96-bit nonce, associated data, 10k nonce uniqueness).

## Attempt Log
- T01: PASS. Server skeleton and pytest/ruff config.
- T02: PASS. Flutter skeleton with pinned dependencies.
- T03: PASS. SQLite tables, create-invite, POST /register.
- T04: PASS. Challenge login, signature verify, token rotation, rate limits.
- T05: PASS. Key directory, WebSocket relay, delete-on-ack, offline delivery, 30-day purge.
- T06: PASS. Server privacy: log redaction, security headers, closed CORS, 1MB size limit.
- T07: PASS. TOTP enrolment, Argon2id recovery codes, new-device approval flow.
