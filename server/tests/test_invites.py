import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from app.database import create_invite, get_db_connection, init_db
from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture(autouse=True)
def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_securechat.db"
    monkeypatch.setenv("DATABASE_PATH", str(db_file))
    init_db(str(db_file))
    return str(db_file)


def test_valid_invite(test_db):
    invite_code = create_invite(db_path=test_db, expires_in_seconds=3600)
    payload = {
        "invite_code": invite_code,
        "user_id": "alice_123",
        "device_id": "dev_alice_1",
        "device_signing_pub": "pub_sign_alice_abc123",
        "device_encryption_pub": "pub_enc_alice_xyz789",
    }
    response = client.post("/register", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["user_id"] == "alice_123"
    assert data["device_id"] == "dev_alice_1"

    # Verify database state
    conn = get_db_connection(test_db)
    user = conn.execute("SELECT * FROM users WHERE id = ?", ("alice_123",)).fetchone()
    assert user is not None
    device = conn.execute("SELECT * FROM devices WHERE id = ?", ("dev_alice_1",)).fetchone()
    assert device is not None
    invite = conn.execute("SELECT * FROM invites WHERE code = ?", (invite_code,)).fetchone()
    assert invite["used"] == 1
    conn.close()


def test_reused_invite(test_db):
    invite_code = create_invite(db_path=test_db, expires_in_seconds=3600)
    payload1 = {
        "invite_code": invite_code,
        "user_id": "alice_123",
        "device_id": "dev_alice_1",
        "device_signing_pub": "pub_sign_1",
        "device_encryption_pub": "pub_enc_1",
    }
    res1 = client.post("/register", json=payload1)
    assert res1.status_code == 200

    payload2 = {
        "invite_code": invite_code,
        "user_id": "bob_456",
        "device_id": "dev_bob_1",
        "device_signing_pub": "pub_sign_2",
        "device_encryption_pub": "pub_enc_2",
    }
    res2 = client.post("/register", json=payload2)
    assert res2.status_code == 400
    assert "used" in res2.json()["detail"].lower()


def test_expired_invite(test_db):
    # Create invite that expired in the past
    now = int(time.time())
    conn = get_db_connection(test_db)
    conn.execute(
        "INSERT INTO invites (code, created_at, expires_at, used) VALUES (?, ?, ?, 0)",
        ("expired_code_123", now - 3600, now - 10),
    )
    conn.commit()
    conn.close()

    payload = {
        "invite_code": "expired_code_123",
        "user_id": "carol_789",
        "device_id": "dev_carol_1",
        "device_signing_pub": "pub_sign_carol",
        "device_encryption_pub": "pub_enc_carol",
    }
    response = client.post("/register", json=payload)
    assert response.status_code == 400
    assert "expired" in response.json()["detail"].lower()


def test_invalid_invite(test_db):
    payload = {
        "invite_code": "non_existent_code_999",
        "user_id": "eve_000",
        "device_id": "dev_eve_1",
        "device_signing_pub": "pub_sign_eve",
        "device_encryption_pub": "pub_enc_eve",
    }
    response = client.post("/register", json=payload)
    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()


def test_manage_create_invite(test_db):
    manage_py = Path(__file__).resolve().parent.parent / "manage.py"
    env = os.environ.copy()
    env["DATABASE_PATH"] = test_db
    res = subprocess.run(
        [sys.executable, str(manage_py), "create-invite"],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    code = res.stdout.strip()
    assert len(code) >= 16

    # Verify code exists in DB
    conn = get_db_connection(test_db)
    row = conn.execute("SELECT * FROM invites WHERE code = ?", (code,)).fetchone()
    assert row is not None
    assert row["used"] == 0
    conn.close()
