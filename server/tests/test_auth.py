import base64
import time

import pytest
from app.database import create_invite, get_db_connection, init_db
from app.main import app
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture(autouse=True)
def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_auth.db"
    monkeypatch.setenv("DATABASE_PATH", str(db_file))
    init_db(str(db_file))
    return str(db_file)


def generate_p256_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv, pub_pem


def register_test_device(test_db, user_id="alice", device_id="dev_1"):
    priv_key, pub_pem = generate_p256_keypair()
    invite_code = create_invite(db_path=test_db)
    res = client.post(
        "/register",
        json={
            "invite_code": invite_code,
            "user_id": user_id,
            "device_id": device_id,
            "device_signing_pub": pub_pem,
            "device_encryption_pub": "dummy_rsa_pub_pem",
        },
    )
    assert res.status_code == 200
    return priv_key, pub_pem


def test_challenge_and_verify_success(test_db):
    priv_key, _ = register_test_device(test_db)

    # 1. Request challenge
    res = client.post("/auth/challenge", json={"user_id": "alice", "device_id": "dev_1"})
    assert res.status_code == 200
    data = res.json()
    nonce = data["nonce"]
    assert len(nonce) >= 32
    assert data["expires_in"] == 60

    # 2. Sign nonce
    sig = priv_key.sign(nonce.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    sig_b64 = base64.b64encode(sig).decode("utf-8")

    # 3. Verify
    res_verify = client.post(
        "/auth/verify",
        json={
            "user_id": "alice",
            "device_id": "dev_1",
            "nonce": nonce,
            "signature": sig_b64,
        },
    )
    assert res_verify.status_code == 200
    tokens = res_verify.json()
    assert "access_token" in tokens
    assert tokens["expires_in"] == 600
    assert "refresh_token" in tokens


def test_replayed_nonce(test_db):
    priv_key, _ = register_test_device(test_db)
    res = client.post("/auth/challenge", json={"user_id": "alice", "device_id": "dev_1"})
    nonce = res.json()["nonce"]
    sig = base64.b64encode(priv_key.sign(nonce.encode("utf-8"), ec.ECDSA(hashes.SHA256()))).decode()

    # First verify passes
    res1 = client.post(
        "/auth/verify",
        json={"user_id": "alice", "device_id": "dev_1", "nonce": nonce, "signature": sig},
    )
    assert res1.status_code == 200

    # Replay of same nonce fails
    res2 = client.post(
        "/auth/verify",
        json={"user_id": "alice", "device_id": "dev_1", "nonce": nonce, "signature": sig},
    )
    assert res2.status_code == 400
    assert "replayed" in res2.json()["detail"].lower() or "invalid" in res2.json()["detail"].lower()


def test_expired_nonce(test_db):
    priv_key, _ = register_test_device(test_db)
    # Insert challenge directly with expired timestamp
    conn = get_db_connection(test_db)
    past = int(time.time()) - 100
    conn.execute(
        """
        INSERT INTO auth_challenges (nonce, user_id, device_id, expires_at, used)
        VALUES (?, ?, ?, ?, 0)
        """,
        ("expired_nonce_12345", "alice", "dev_1", past),
    )
    conn.commit()
    conn.close()

    sig = base64.b64encode(
        priv_key.sign("expired_nonce_12345".encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    ).decode()
    res = client.post(
        "/auth/verify",
        json={
            "user_id": "alice",
            "device_id": "dev_1",
            "nonce": "expired_nonce_12345",
            "signature": sig,
        },
    )
    assert res.status_code == 400
    assert "expired" in res.json()["detail"].lower()


def test_bad_signature(test_db):
    _, _ = register_test_device(test_db)
    # Generate another key pair (impostor)
    wrong_key, _ = generate_p256_keypair()

    res = client.post("/auth/challenge", json={"user_id": "alice", "device_id": "dev_1"})
    nonce = res.json()["nonce"]
    bad_sig = base64.b64encode(
        wrong_key.sign(nonce.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    ).decode()

    res_verify = client.post(
        "/auth/verify",
        json={"user_id": "alice", "device_id": "dev_1", "nonce": nonce, "signature": bad_sig},
    )
    assert res_verify.status_code == 401
    assert "signature" in res_verify.json()["detail"].lower()


def test_refresh_token_rotation_and_family_revocation(test_db):
    priv_key, _ = register_test_device(test_db)
    res = client.post("/auth/challenge", json={"user_id": "alice", "device_id": "dev_1"})
    nonce = res.json()["nonce"]
    sig_raw = priv_key.sign(nonce.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    sig = base64.b64encode(sig_raw).decode()
    res_verify = client.post(
        "/auth/verify",
        json={"user_id": "alice", "device_id": "dev_1", "nonce": nonce, "signature": sig},
    )
    tokens = res_verify.json()
    r1 = tokens["refresh_token"]

    # 1. Rotate refresh token: exchange r1 for r2
    res_rot = client.post("/auth/refresh", json={"refresh_token": r1})
    assert res_rot.status_code == 200
    rot_data = res_rot.json()
    r2 = rot_data["refresh_token"]
    assert r2 != r1
    assert "access_token" in rot_data

    # 2. Reusing old refresh token r1 must fail AND revoke token family
    res_reuse = client.post("/auth/refresh", json={"refresh_token": r1})
    assert res_reuse.status_code == 401
    detail = res_reuse.json()["detail"].lower()
    assert "revoked" in detail or "reuse" in detail

    # 3. Now r2 is also revoked because the entire family was revoked upon reuse!
    res_r2 = client.post("/auth/refresh", json={"refresh_token": r2})
    assert res_r2.status_code == 401


def test_rate_limiting(test_db):
    # Rapid requests to /auth/challenge from same IP/device trigger 429
    priv_key, _ = register_test_device(test_db, user_id="ratelimited", device_id="dev_rl")
    status_codes = []
    for _ in range(35):
        r = client.post("/auth/challenge", json={"user_id": "ratelimited", "device_id": "dev_rl"})
        status_codes.append(r.status_code)

    assert 429 in status_codes
