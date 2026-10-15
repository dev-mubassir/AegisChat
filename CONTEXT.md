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
- Challenge login: 60s one-time nonces signed with ECDSA P-256 (SHA-256).
- Auth returns 10-minute HMAC-SHA256 access tokens and 30-day rotating refresh tokens.
- Reusing an old refresh token immediately revokes the entire token family.
- Sliding window rate limiting applied to /register and /auth/* per IP and device.

## What Is Next
- T05: Key directory and message relay (GET /keys/{user_id}, WebSocket /ws, ack & delete, offline delivery).

## Attempt Log
- T01: PASS. Repo and server skeleton with /health.
- T02: PASS. Flutter skeleton with pinned dependencies; analyze and test green.
- T03: PASS. SQLite tables, manage.py create-invite, POST /register with invite verification.
- T04: PASS. Challenge login, ECDSA signature verification, token rotation, family revocation on reuse, rate limits.
