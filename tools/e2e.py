#!/usr/bin/env python3
"""End-to-end integration test runner for SecureChat.

Orchestrates:
1. Temporary SQLite database and server log setup.
2. Generating test invites.
3. Spawning FastAPI backend server on a free ephemeral port.
4. Polling /health until ready.
5. Executing headless Flutter/Dart client test (app/test_e2e/e2e_test.dart).
6. Verifying that the secret plaintext appears NOWHERE in server database or logs.
7. Verifying that ack deletes the message from the server relay table.
"""

import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

REPO_ROOT = Path(__file__).resolve().parent.parent
SECRET_PLAINTEXT = "SECURECHAT_TOP_SECRET_E2E_MESSAGE_772183"


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_health(url: str, timeout_sec: float = 15.0) -> bool:
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            req = urllib.request.Request(f"{url}/health")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.2)
    return False


def main() -> int:
    port = find_free_port()
    server_url = f"http://127.0.0.1:{port}"

    flutter_cmd = (
        r"C:\src\flutter\bin\flutter.bat"
        if os.name == "nt"
        else shutil.which("flutter") or "flutter"
    )

    with tempfile.TemporaryDirectory(prefix="securechat_e2e_") as tmpdir:
        tmp_path = Path(tmpdir)
        db_path = tmp_path / "e2e_test.db"
        log_path = tmp_path / "server.log"

        # 1. Initialize DB and create invites
        sys.path.insert(0, str(REPO_ROOT / "server"))
        from app.database import init_db

        init_db(str(db_path))

        invite1 = f"INV-E2E-ALICE-{secrets.token_hex(4)}"
        invite2 = f"INV-E2E-BOB-{secrets.token_hex(4)}"
        now = int(time.time())

        conn = sqlite3.connect(str(db_path))
        with conn:
            conn.execute(
                "INSERT INTO invites (code, created_at, expires_at, used) VALUES (?, ?, ?, 0)",
                (invite1, now, now + 3600),
            )
            conn.execute(
                "INSERT INTO invites (code, created_at, expires_at, used) VALUES (?, ?, ?, 0)",
                (invite2, now, now + 3600),
            )
        conn.close()

        # 2. Launch FastAPI server
        server_env = os.environ.copy()
        server_env["DATABASE_PATH"] = str(db_path)
        server_env["PYTHONPATH"] = str(REPO_ROOT / "server")

        log_file = open(log_path, "w", encoding="utf-8")
        server_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "info",
            ],
            cwd=str(REPO_ROOT / "server"),
            env=server_env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

        try:
            print(f"[*] Starting SecureChat server on {server_url}...")
            if not wait_for_health(server_url):
                print("[!] Server failed to start within timeout.")
                log_file.flush()
                print(log_path.read_text(encoding="utf-8", errors="ignore"))
                return 1
            print("[+] Server healthy.")

            # 3. Run Dart headless E2E test
            test_env = os.environ.copy()
            test_env["SECURECHAT_SERVER_URL"] = server_url
            test_env["SECURECHAT_INVITE_1"] = invite1
            test_env["SECURECHAT_INVITE_2"] = invite2

            print("[*] Running headless Flutter/Dart E2E test...")
            test_res = subprocess.run(
                [flutter_cmd, "test", "test_e2e/e2e_test.dart"],
                cwd=str(REPO_ROOT / "app"),
                env=test_env,
                capture_output=True,
                text=True,
            )

            print(test_res.stdout)
            if test_res.returncode != 0:
                print(test_res.stderr)
                print(
                    f"[FAIL] Flutter E2E test failed with exit code {test_res.returncode}"
                )
                print("\n--- SERVER LOG ---")
                log_file.flush()
                print(log_path.read_text("utf-8", errors="ignore"))
                print("--- END SERVER LOG ---\n")
                return 1

            print("[PASS] Flutter E2E test succeeded.")

        finally:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
            log_file.close()

        # 4. Security Audit: Check that server DB holds NO plaintext
        db_bytes = db_path.read_bytes()
        if SECRET_PLAINTEXT.encode("utf-8") in db_bytes:
            print(
                "[FAIL] SECURITY INVARIANT VIOLATED: Plaintext message found in server database file!"
            )
            return 1

        # Check DB rows
        conn = sqlite3.connect(str(db_path))
        messages_rows = conn.execute("SELECT * FROM messages").fetchall()
        if len(messages_rows) != 0:
            print(
                f"[FAIL] Expected 0 delivered messages in server DB, found {len(messages_rows)}!"
            )
            return 1
        conn.close()

        # 5. Security Audit: Check that server log holds NO plaintext
        log_content = log_path.read_text("utf-8", errors="ignore")
        if SECRET_PLAINTEXT in log_content:
            print(
                "[FAIL] SECURITY INVARIANT VIOLATED: Plaintext message found in server logs!"
            )
            return 1

        print("[PASS] Server database and logs hold zero plaintext.")
        print("[PASS] Message was cleanly purged upon delivery ack.")
        print("[PASS] End-to-end integration test completed successfully.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
