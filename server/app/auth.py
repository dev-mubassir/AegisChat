"""Authentication and cryptography primitives for SecureChat server."""

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException

from app.database import get_db_connection

# Server HMAC secret for access tokens
_SERVER_SECRET = secrets.token_bytes(32)

# In-memory sliding window rate limiter
_rate_limits: dict[str, list[float]] = defaultdict(list)


def reset_rate_limits() -> None:
    _rate_limits.clear()


def check_rate_limit(key: str, max_requests: int = 30, window_seconds: int = 60) -> None:
    now = time.time()
    timestamps = _rate_limits[key]
    # Prune old timestamps
    cutoff = now - window_seconds
    _rate_limits[key] = [t for t in timestamps if t > cutoff]
    if len(_rate_limits[key]) >= max_requests:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please try again later.",
        )
    _rate_limits[key].append(now)


def create_access_token(user_id: str, device_id: str, expires_in: int = 600) -> str:
    now = int(time.time())
    payload = {
        "user_id": user_id,
        "device_id": device_id,
        "iat": now,
        "exp": now + expires_in,
    }
    header_b64 = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode().rstrip("=")
    )
    sig_material = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(_SERVER_SECRET, sig_material, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_access_token(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=401, detail="Invalid token format")
    header_b64, payload_b64, sig_b64 = parts
    sig_material = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(_SERVER_SECRET, sig_material, hashlib.sha256).digest()

    def _pad(s: str) -> str:
        return s + "=" * (-len(s) % 4)

    try:
        provided_sig = base64.urlsafe_b64decode(_pad(sig_b64))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token signature encoding")

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise HTTPException(status_code=401, detail="Invalid token signature")

    try:
        payload = json.loads(base64.urlsafe_b64decode(_pad(payload_b64)).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    if payload.get("exp", 0) < int(time.time()):
        raise HTTPException(status_code=401, detail="Token has expired")

    return payload


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_refresh_token(user_id: str, device_id: str, family_id: str | None = None) -> str:
    token = secrets.token_urlsafe(32)
    thash = hash_token(token)
    now = int(time.time())
    expires_at = now + 30 * 86400  # 30 days
    token_id = secrets.token_hex(16)
    fam_id = family_id or secrets.token_hex(16)

    conn = get_db_connection()
    with conn:
        conn.execute(
            """
            INSERT INTO refresh_tokens (
                id, token_hash, user_id, device_id, family_id, expires_at, revoked, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (token_id, thash, user_id, device_id, fam_id, expires_at, now),
        )
    conn.close()
    return token


def rotate_refresh_token(old_token: str) -> tuple[str, str, str]:
    thash = hash_token(old_token)
    now = int(time.time())
    conn = get_db_connection()
    with conn:
        row = conn.execute(
            """
            SELECT id, user_id, device_id, family_id, expires_at, revoked
            FROM refresh_tokens WHERE token_hash = ?
            """,
            (thash,),
        ).fetchone()

        if not row:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        family_id = row["family_id"]
        # If token was already revoked or expired -> REUSE DETECTED!
        if row["revoked"] != 0 or row["expires_at"] <= now:
            # Revoke entire token family
            conn.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?",
                (family_id,),
            )
            conn.commit()
            raise HTTPException(
                status_code=401,
                detail="Refresh token reuse detected. Token family revoked.",
            )

        # Mark current token as revoked (rotated)
        conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?", (row["id"],))

        user_id = row["user_id"]
        device_id = row["device_id"]

    conn.close()

    new_refresh = issue_refresh_token(user_id, device_id, family_id=family_id)
    new_access = create_access_token(user_id, device_id)
    return new_access, new_refresh, user_id


def verify_ecdsa_signature(pub_pem: str, message: bytes, signature_b64: str) -> bool:
    try:
        sig_bytes = base64.b64decode(signature_b64)
        public_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        public_key.verify(sig_bytes, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False
