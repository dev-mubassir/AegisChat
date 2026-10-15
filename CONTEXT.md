# SecureChat Context & Handoff

## Environment & Tool Versions
- OS: Windows (win32, x64)
- Python: 3.14.7 | Git: 2.55.0.windows.3
- Flutter: 3.47.7 (channel stable) | Dart: 3.13.5
- Pytest: 9.1.1 | Ruff: 0.17.0 | FastAPI: 0.143.1

## Commands That Work
- S: `cd server && python -m pytest -q`
- Ruff: `python -m ruff check server`
- Flutter version: `flutter --version` (or `C:\src\flutter\bin\flutter.bat --version`)

## Decisions
- Flutter installed in `C:\src\flutter`, added to User PATH and `loop.py`.
- Server layout: `server/app/main.py` with `/health`, `server/tests/test_health.py`.
- Formatted with ruff, configured with `pyproject.toml` and `server/pytest.ini`.

## What Is Next
- T02: Flutter skeleton (`flutter create app --platforms android,ios`), add dependencies.

## Attempt Log
- T01: PASS. Initialized git repo, added .gitignore, server skeleton with /health, pinned requirements, pytest and ruff configs.
