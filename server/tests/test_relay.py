import base64
import time

import pytest
from app.auth import create_access_token
from app.database import (
    create_invite,
    get_db_connection,
    init_db,
    purge_expired_messages,
)
from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture(autouse=True)
def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_relay.db"
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
    token = create_access_token(user_id, device_id)
    return token


def test_get_keys(test_db):
    alice_token = register_user(test_db, "alice", "dev_alice")
    register_user(test_db, "bob", "dev_bob")

    # 1. Unauthenticated request -> 401
    res_no_auth = client.get("/keys/bob")
    assert res_no_auth.status_code == 401

    # 2. Invalid token -> 401
    res_bad_auth = client.get(
        "/keys/bob", headers={"Authorization": "Bearer invalid.token.here"}
    )
    assert res_bad_auth.status_code == 401

    # 3. Authenticated request -> 200 with keys
    res = client.get(
        "/keys/bob", headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["user_id"] == "bob"
    assert len(data["devices"]) == 1
    dev = data["devices"][0]
    assert dev["device_id"] == "dev_bob"
    assert dev["device_signing_pub"] == "pub_sign_bob"
    assert dev["device_encryption_pub"] == "pub_enc_bob"

    # 4. Non-existent user -> 404
    res_404 = client.get(
        "/keys/unknown_user", headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert res_404.status_code == 404


def test_ws_unauthorized():
    with pytest.raises(Exception):
        with client.websocket_connect("/ws?token=bad_token"):
            pass


def test_ws_delivery_and_delete_on_ack(test_db):
    alice_token = register_user(test_db, "alice", "dev_alice")
    bob_token = register_user(test_db, "bob", "dev_bob")

    ciphertext_bytes = b"encrypted_secret_payload_12345"
    ct_b64 = base64.b64encode(ciphertext_bytes).decode("utf-8")

    # 1. Alice connects and sends message to Bob
    with client.websocket_connect(f"/ws?token={alice_token}") as alice_ws:
        alice_ws.send_json(
            {
                "action": "send",
                "message_id": "msg_001",
                "recipient_id": "bob",
                "ciphertext_b64": ct_b64,
            }
        )

    # 2. Message is stored in database
    conn = get_db_connection(test_db)
    row = conn.execute(
        "SELECT * FROM messages WHERE id = ?", ("msg_001",)
    ).fetchone()
    assert row is not None
    assert row["sender_id"] == "alice"
    assert row["recipient_id"] == "bob"
    conn.close()

    # 3. Bob connects and receives the pending message
    with client.websocket_connect(f"/ws?token={bob_token}") as bob_ws:
        msg = bob_ws.receive_json()
        assert msg["type"] == "message"
        assert msg["message_id"] == "msg_001"
        assert msg["sender_id"] == "alice"
        assert msg["ciphertext_b64"] == ct_b64

        # Bob sends ack
        bob_ws.send_json({"action": "ack", "message_id": "msg_001"})
        ack_reply = bob_ws.receive_json()
        assert ack_reply["status"] == "ack_ok"

    # 4. Message must be deleted from DB upon delivery ack!
    conn = get_db_connection(test_db)
    row_after = conn.execute(
        "SELECT * FROM messages WHERE id = ?", ("msg_001",)
    ).fetchone()
    assert row_after is None
    conn.close()


def test_ws_offline_delivery(test_db):
    alice_token = register_user(test_db, "alice", "dev_alice")
    bob_token = register_user(test_db, "bob", "dev_bob")

    ct_b64 = base64.b64encode(b"offline_message_content").decode("utf-8")

    # Alice connects while Bob is offline and sends message
    with client.websocket_connect(f"/ws?token={alice_token}") as alice_ws:
        alice_ws.send_json(
            {
                "action": "send",
                "message_id": "msg_offline_1",
                "recipient_id": "bob",
                "ciphertext_b64": ct_b64,
            }
        )

    # Message is queued in DB
    conn = get_db_connection(test_db)
    row = conn.execute(
        "SELECT * FROM messages WHERE id = ?", ("msg_offline_1",)
    ).fetchone()
    assert row is not None
    conn.close()

    # Bob connects later -> receives queued message
    with client.websocket_connect(f"/ws?token={bob_token}") as bob_ws:
        msg = bob_ws.receive_json()
        assert msg["type"] == "message"
        assert msg["message_id"] == "msg_offline_1"
        assert msg["sender_id"] == "alice"
        assert msg["ciphertext_b64"] == ct_b64

        # Bob acks
        bob_ws.send_json({"action": "ack", "message_id": "msg_offline_1"})
        bob_ws.receive_json()

    # Message is now deleted
    conn = get_db_connection(test_db)
    row_after = conn.execute(
        "SELECT * FROM messages WHERE id = ?", ("msg_offline_1",)
    ).fetchone()
    assert row_after is None
    conn.close()


def test_ws_oversize_message(test_db):
    alice_token = register_user(test_db, "alice", "dev_alice")
    # Message larger than 64 KB
    huge_bytes = b"A" * (70 * 1024)
    huge_b64 = base64.b64encode(huge_bytes).decode("utf-8")

    with client.websocket_connect(f"/ws?token={alice_token}") as alice_ws:
        alice_ws.send_json(
            {
                "action": "send",
                "message_id": "msg_oversize",
                "recipient_id": "bob",
                "ciphertext_b64": huge_b64,
            }
        )
        reply = alice_ws.receive_json()
        assert reply["type"] == "error"
        assert "oversize" in reply["detail"].lower() or "limit" in reply["detail"].lower()


def test_purge_old_messages(test_db):
    now = int(time.time())
    old_time = now - (31 * 86400)  # 31 days old
    conn = get_db_connection(test_db)
    with conn:
        conn.execute(
            """
            INSERT INTO messages (id, sender_id, recipient_id, ciphertext, created_at, delivered)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            ("msg_old", "alice", "bob", b"old_ciphertext", old_time),
        )
        conn.execute(
            """
            INSERT INTO messages (id, sender_id, recipient_id, ciphertext, created_at, delivered)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            ("msg_new", "alice", "bob", b"new_ciphertext", now),
        )
    conn.close()

    deleted = purge_expired_messages(db_path=test_db, max_age_seconds=30 * 86400)
    assert deleted >= 1

    conn = get_db_connection(test_db)
    assert conn.execute("SELECT * FROM messages WHERE id = 'msg_old'").fetchone() is None
    assert conn.execute("SELECT * FROM messages WHERE id = 'msg_new'").fetchone() is not None
    conn.close()
