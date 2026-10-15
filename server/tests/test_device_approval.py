import base64
import json

import pyotp
import pytest
from app.auth import create_access_token
from app.database import create_invite, get_db_connection, init_db
from app.main import app
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture(autouse=True)
def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_totp.db"
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


def register_user_with_key(test_db, user_id, device_id):
    priv_key, pub_pem = generate_p256_keypair()
    invite = create_invite(db_path=test_db)
    res = client.post(
        "/register",
        json={
            "invite_code": invite,
            "user_id": user_id,
            "device_id": device_id,
            "device_signing_pub": pub_pem,
            "device_encryption_pub": f"pub_enc_{user_id}",
        },
    )
    assert res.status_code == 200
    token = create_access_token(user_id, device_id)
    return priv_key, pub_pem, token


def test_totp_enrolment_and_check(test_db):
    _, _, token = register_user_with_key(test_db, "alice", "dev_old")

    # 1. Enrol TOTP
    res = client.post("/auth/totp/enroll", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    secret = data["secret"]
    codes = data["recovery_codes"]
    assert len(codes) == 10

    # 2. Confirm enrollment with code
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    res_confirm = client.post(
        "/auth/totp/confirm",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": valid_code},
    )
    assert res_confirm.status_code == 200


def test_wrong_totp_code(test_db):
    _, _, token = register_user_with_key(test_db, "alice", "dev_old")
    client.post("/auth/totp/enroll", headers={"Authorization": f"Bearer {token}"})

    res = client.post(
        "/auth/totp/confirm",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": "000000"},
    )
    assert res.status_code == 400
    assert "wrong" in res.json()["detail"].lower() or "invalid" in res.json()["detail"].lower()


def test_reused_recovery_code(test_db):
    _, _, token = register_user_with_key(test_db, "alice", "dev_old")
    enrol_res = client.post("/auth/totp/enroll", headers={"Authorization": f"Bearer {token}"})
    rec_code = enrol_res.json()["recovery_codes"][0]

    # Use recovery code first time
    res1 = client.post(
        "/auth/totp/check",
        json={"user_id": "alice", "code": rec_code},
    )
    assert res1.status_code == 200

    # Reusing the single-use recovery code must fail
    res2 = client.post(
        "/auth/totp/check",
        json={"user_id": "alice", "code": rec_code},
    )
    assert res2.status_code == 400
    assert "used" in res2.json()["detail"].lower() or "invalid" in res2.json()["detail"].lower()


def test_new_device_approval_success(test_db):
    old_priv, _, token = register_user_with_key(test_db, "alice", "dev_old")
    enrol_res = client.post("/auth/totp/enroll", headers={"Authorization": f"Bearer {token}"})
    secret = enrol_res.json()["secret"]
    valid_totp = pyotp.TOTP(secret).now()

    # Generate new device keys
    new_priv, new_pub = generate_p256_keypair()

    payload_dict = {
        "user_id": "alice",
        "new_device_id": "dev_new",
        "new_device_signing_pub": new_pub,
        "new_device_encryption_pub": "rsa_pub_new",
    }
    payload_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    sig = base64.b64encode(old_priv.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))).decode()

    res = client.post(
        "/devices/approve",
        json={
            "user_id": "alice",
            "old_device_id": "dev_old",
            "new_device_id": "dev_new",
            "new_device_signing_pub": new_pub,
            "new_device_encryption_pub": "rsa_pub_new",
            "approval_signature": sig,
            "totp_code": valid_totp,
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

    # Verify new device is registered in DB
    conn = get_db_connection(test_db)
    dev = conn.execute("SELECT * FROM devices WHERE id = 'dev_new'").fetchone()
    assert dev is not None
    conn.close()


def test_approval_from_unknown_device(test_db):
    register_user_with_key(test_db, "alice", "dev_old")
    unknown_priv, _ = generate_p256_keypair()
    _, new_pub = generate_p256_keypair()

    payload_dict = {
        "user_id": "alice",
        "new_device_id": "dev_new",
        "new_device_signing_pub": new_pub,
        "new_device_encryption_pub": "rsa_pub_new",
    }
    payload_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    sig = base64.b64encode(unknown_priv.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))).decode()

    res = client.post(
        "/devices/approve",
        json={
            "user_id": "alice",
            "old_device_id": "dev_impostor_unknown",
            "new_device_id": "dev_new",
            "new_device_signing_pub": new_pub,
            "new_device_encryption_pub": "rsa_pub_new",
            "approval_signature": sig,
            "totp_code": "123456",
        },
    )
    assert res.status_code in (400, 404)
    assert "unknown" in res.json()["detail"].lower() or "not found" in res.json()["detail"].lower()
