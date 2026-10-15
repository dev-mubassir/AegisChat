# SecureChat Context & Handoff

## Environment & Tool Versions
- OS: Windows (win32, x64)
- Python: 3.14.7 | Git: 2.55.0.windows.3
- Flutter: 3.47.7 (channel stable, revision abaf9c5237)
- Dart: 3.13.5 | DevTools: 2.60.0
- Pytest: 9.1.1 | Ruff: 0.17.0 | FastAPI: 0.143.1

## Commands That Work
- S: `cd server && python -m pytest -q`
- Ruff: `python -m ruff check server`
- A: `cd app && C:\src\flutter\bin\flutter.bat analyze && C:\src\flutter\bin\flutter.bat test`
- Flutter version: `C:\src\flutter\bin\flutter.bat --version`

## Decisions
- Flutter 3.47.7 installed in `C:\src\flutter`.
- App created with `--platforms android,ios`.
- Pinned exact versions for: cryptography, pointycastle, flutter_secure_storage, local_auth, web_socket_channel, http, qr_flutter, mobile_scanner, flutter_lints.

## What Is Next
- T03: Database and invites (SQLite tables, manage.py create-invite, POST /register).

## Attempt Log
- T01: PASS. Repo and server skeleton with /health endpoint.
- T02: PASS. Flutter skeleton with pinned crypto and security packages; analyze and test green.
