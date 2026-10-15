# SecureChat Context & Handoff

## Environment & Tool Versions
- OS: Windows (win32, x64)
- Python: 3.14.7 | Git: 2.55.0.windows.3
- Flutter: 3.47.7 (channel stable) | Dart: 3.13.5
- Pytest: 9.1.1 | Ruff: 0.17.0 | FastAPI: 0.143.1

## Commands That Work
- S: `cd server && python -m pytest -q`
- Ruff: `python -m ruff check server`
- A: `cd app && C:\src\flutter\bin\flutter.bat analyze && C:\src\flutter\bin\flutter.bat test`
- CLI Invite: `python server/manage.py create-invite`

## Decisions
- SQLite schema: users, devices, invites, messages, refresh_tokens.
- POST /register checks invite validity, expiration, and single-use, then inserts user & device.
- manage.py CLI creates cryptographically secure URL-safe invite tokens.

## What Is Next
- T04: Challenge login and tokens (POST /auth/challenge, POST /auth/verify, rate limits).

## Attempt Log
- T01: PASS. Server skeleton and pytest/ruff config.
- T02: PASS. Flutter skeleton with pinned security/crypto dependencies.
- T03: PASS. SQLite tables, manage.py create-invite, POST /register with invite verification.
