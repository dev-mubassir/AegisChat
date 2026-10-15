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
- Server privacy middleware enforces: max 1MB request size, strict security headers (CSP, HSTS, XFO, nosniff, referrer-policy, permissions-policy).
- Logs are strictly redacted: only method, path, status, and latency are logged; bodies and tokens never appear.
- Verified zero-plaintext in SQLite and server logs.

## What Is Next
- T07: TOTP, recovery codes, new-device approval (pyotp, Argon2id, QR payload approval).

## Attempt Log
- T01: PASS. Server skeleton and pytest/ruff config.
- T02: PASS. Flutter skeleton with pinned dependencies.
- T03: PASS. SQLite tables, create-invite, POST /register.
- T04: PASS. Challenge login, signature verify, token rotation & revocation, rate limits.
- T05: PASS. Key directory, WebSocket relay, delete-on-ack, offline delivery, 30-day purge.
- T06: PASS. Server privacy: log redaction, security headers, closed CORS, 1MB size limit.
