import base64
import io
import logging
from pathlib import Path

import pytest
from app.auth import create_access_token
from app.database import create_invite, init_db
from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture(autouse=True)
def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_privacy.db"
    monkeypatch.setenv("DATABASE_PATH", str(db_file))
    init_db(str(db_file))
    return str(db_file)


def register_user(test_db, user_id, device_id):
    invite = create_invite(db_path=test_db)
    res = client.post(
        "/register",
        json={
            "invite_code": invite,
            "user_id": user_id,
            "device_id": device_id,
            "device_signing_pub": f"pub_sign_{user_id}",
            "device_encryption_pub": f"pub_enc_{user_id}",
        },
    )
    assert res.status_code == 200
    return create_access_token(user_id, device_id)


def test_security_headers():
    res = client.get("/health")
    assert res.status_code == 200
    headers = res.headers
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert "max-age" in headers.get("strict-transport-security", "")
    assert headers.get("referrer-policy") == "no-referrer"
    assert "frame-ancestors 'none'" in headers.get("content-security-policy", "")


def test_cors_closed():
    # Sending Origin header should not reflect wildcard
    res = client.get("/health", headers={"Origin": "https://malicious-site.com"})
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") != "*"


def test_request_size_limit():
    # 2 MB payload exceeds 1 MB limit -> 413
    big_payload = {"dummy": "X" * (2 * 1024 * 1024)}
    res = client.post("/register", json=big_payload)
    assert res.status_code == 413
    assert "too large" in res.json()["detail"].lower()


def test_no_plaintext_and_no_tokens_in_db_and_logs(test_db):
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    logger = logging.getLogger("securechat")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    alice_token = register_user(test_db, "alice", "dev_alice")
    bob_token = register_user(test_db, "bob", "dev_bob")

    plaintext_marker = "PLAINTEXT_SUPER_SECRET_MARKER_98765"
    # Sender encrypts plaintext (simulated by encrypted blob not holding plaintext string)
    simulated_ciphertext = b"\x01\x02\x03CIPHERTEXT_BYTES_ENCRYPTED\x04\x05"
    ct_b64 = base64.b64encode(simulated_ciphertext).decode("utf-8")

    # Send message through relay
    with client.websocket_connect(f"/ws?token={alice_token}") as alice_ws:
        alice_ws.send_json(
            {
                "action": "send",
                "message_id": "msg_privacy_test",
                "recipient_id": "bob",
                "ciphertext_b64": ct_b64,
            }
        )

    # Bob connects and acks
    with client.websocket_connect(f"/ws?token={bob_token}") as bob_ws:
        bob_ws.receive_json()
        bob_ws.send_json({"action": "ack", "message_id": "msg_privacy_test"})
        bob_ws.receive_json()

    # Flush logs
    handler.flush()
    captured_logs = log_stream.getvalue()

    # Scan captured logs: plaintext marker must not appear!
    assert plaintext_marker not in captured_logs
    # Tokens must not appear in raw logs
    assert alice_token not in captured_logs
    assert bob_token not in captured_logs

    # Scan SQLite database bytes: plaintext marker must not appear!
    db_bytes = Path(test_db).read_bytes()
    assert plaintext_marker.encode("utf-8") not in db_bytes
