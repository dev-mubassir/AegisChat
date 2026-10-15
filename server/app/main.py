"""Main FastAPI application for SecureChat."""

import base64
import json
import logging
import secrets
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import (
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.auth import (
    check_rate_limit,
    create_access_token,
    issue_refresh_token,
    rotate_refresh_token,
    verify_access_token,
    verify_ecdsa_signature,
)
from app.database import get_db_connection, init_db

logger = logging.getLogger("securechat")
MAX_REQUEST_SIZE = 1024 * 1024  # 1 MB


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    init_db()
    yield


app = FastAPI(title="SecureChat Server", lifespan=lifespan)


@app.middleware("http")
async def security_and_privacy_middleware(request: Request, call_next: Any) -> Any:
    # 1. Check request size limit
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_SIZE:
        return JSONResponse(
            status_code=413,
            content={"detail": "Payload too large. Max request size is 1MB."},
        )

    # 2. Execute call
    start_time = time.time()
    response = await call_next(request)
    duration_ms = (time.time() - start_time) * 1000

    # 3. Log safe metadata only (no bodies, no query strings with tokens, no headers)
    client_ip = request.client.host if request.client else "unknown"
    logger.info(
        "%s %s -> %s (%.2f ms) [client: %s]",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
        client_ip,
    )

    # 4. Attach strict security headers
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "DENY"
    response.headers["strict-transport-security"] = (
        "max-age=63072000; includeSubDomains; preload"
    )
    response.headers["content-security-policy"] = (
        "default-src 'none'; frame-ancestors 'none'"
    )
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["permissions-policy"] = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )

    return response


# Active WebSocket connections: user_id -> list of WebSockets
_active_ws: dict[str, list[WebSocket]] = defaultdict(list)


class RegisterRequest(BaseModel):
    invite_code: str = Field(..., min_length=4)
    user_id: str = Field(..., min_length=3)
    device_id: str = Field(..., min_length=3)
    device_signing_pub: str = Field(..., min_length=1)
    device_encryption_pub: str = Field(..., min_length=1)


class ChallengeRequest(BaseModel):
    user_id: str = Field(..., min_length=3)
    device_id: str = Field(..., min_length=3)


class VerifyRequest(BaseModel):
    user_id: str = Field(..., min_length=3)
    device_id: str = Field(..., min_length=3)
    nonce: str = Field(..., min_length=16)
    signature: str = Field(..., min_length=16)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=16)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "127.0.0.1"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/register")
def register(req: RegisterRequest, request: Request) -> dict[str, str]:
    ip = _client_ip(request)
    check_rate_limit(f"ip:{ip}")
    check_rate_limit(f"dev:{req.device_id}")

    now = int(time.time())
    conn = get_db_connection()
    with conn:
        invite = conn.execute(
            "SELECT code, expires_at, used FROM invites WHERE code = ?",
            (req.invite_code,),
        ).fetchone()

        if not invite:
            raise HTTPException(status_code=400, detail="Invalid invite code")

        if invite["used"] != 0:
            raise HTTPException(status_code=400, detail="Invite already used")

        if invite["expires_at"] <= now:
            raise HTTPException(status_code=400, detail="Invite expired")

        conn.execute(
            "UPDATE invites SET used = 1, used_by = ?, used_at = ? WHERE code = ?",
            (req.user_id, now, req.invite_code),
        )

        conn.execute(
            "INSERT OR IGNORE INTO users (id, created_at) VALUES (?, ?)",
            (req.user_id, now),
        )

        conn.execute(
            """
            INSERT INTO devices (
                id, user_id, device_signing_pub, device_encryption_pub, created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                req.device_id,
                req.user_id,
                req.device_signing_pub,
                req.device_encryption_pub,
                now,
            ),
        )

    conn.close()
    return {"status": "ok", "user_id": req.user_id, "device_id": req.device_id}


@app.post("/auth/challenge")
def auth_challenge(req: ChallengeRequest, request: Request) -> dict[str, Any]:
    ip = _client_ip(request)
    check_rate_limit(f"ip:{ip}")
    check_rate_limit(f"dev:{req.device_id}")

    now = int(time.time())
    conn = get_db_connection()
    with conn:
        device = conn.execute(
            "SELECT id FROM devices WHERE id = ? AND user_id = ?",
            (req.device_id, req.user_id),
        ).fetchone()
        if not device:
            raise HTTPException(status_code=404, detail="Device not registered")

        nonce = secrets.token_urlsafe(32)
        expires_at = now + 60
        conn.execute(
            """
            INSERT INTO auth_challenges (nonce, user_id, device_id, expires_at, used)
            VALUES (?, ?, ?, ?, 0)
            """,
            (nonce, req.user_id, req.device_id, expires_at),
        )
    conn.close()

    return {"nonce": nonce, "expires_in": 60, "expires_at": expires_at}


@app.post("/auth/verify")
def auth_verify(req: VerifyRequest, request: Request) -> dict[str, Any]:
    ip = _client_ip(request)
    check_rate_limit(f"ip:{ip}")
    check_rate_limit(f"dev:{req.device_id}")

    now = int(time.time())
    conn = get_db_connection()
    with conn:
        challenge = conn.execute(
            """
            SELECT nonce, user_id, device_id, expires_at, used
            FROM auth_challenges WHERE nonce = ?
            """,
            (req.nonce,),
        ).fetchone()

        if not challenge or challenge["used"] != 0:
            raise HTTPException(status_code=400, detail="Replayed or invalid challenge nonce")

        if challenge["expires_at"] <= now:
            raise HTTPException(status_code=400, detail="Expired challenge nonce")

        if challenge["user_id"] != req.user_id or challenge["device_id"] != req.device_id:
            raise HTTPException(status_code=400, detail="Challenge device mismatch")

        # Mark challenge as used immediately
        conn.execute("UPDATE auth_challenges SET used = 1 WHERE nonce = ?", (req.nonce,))

        device = conn.execute(
            "SELECT device_signing_pub FROM devices WHERE id = ? AND user_id = ?",
            (req.device_id, req.user_id),
        ).fetchone()

        if not device:
            raise HTTPException(status_code=404, detail="Device not registered")

        pub_pem = device["device_signing_pub"]

    conn.close()

    if not verify_ecdsa_signature(pub_pem, req.nonce.encode("utf-8"), req.signature):
        raise HTTPException(status_code=401, detail="Invalid cryptographic signature")

    access_token = create_access_token(req.user_id, req.device_id, expires_in=600)
    refresh_token = issue_refresh_token(req.user_id, req.device_id)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 600,
        "refresh_token": refresh_token,
    }


@app.post("/auth/refresh")
def auth_refresh(req: RefreshRequest, request: Request) -> dict[str, Any]:
    ip = _client_ip(request)
    check_rate_limit(f"ip:{ip}")

    new_access, new_refresh, _ = rotate_refresh_token(req.refresh_token)
    return {
        "access_token": new_access,
        "token_type": "bearer",
        "expires_in": 600,
        "refresh_token": new_refresh,
    }


@app.get("/keys/{user_id}")
def get_user_keys(
    user_id: str, authorization: str | None = Header(None)
) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.split(" ", 1)[1]
    verify_access_token(token)

    conn = get_db_connection()
    user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    rows = conn.execute(
        """
        SELECT id, device_signing_pub, device_encryption_pub
        FROM devices WHERE user_id = ?
        """,
        (user_id,),
    ).fetchall()
    conn.close()

    devices = [
        {
            "device_id": row["id"],
            "device_signing_pub": row["device_signing_pub"],
            "device_encryption_pub": row["device_encryption_pub"],
        }
        for row in rows
    ]
    return {"user_id": user_id, "devices": devices}


@app.websocket("/ws")
async def websocket_relay(
    websocket: WebSocket, token: str | None = Query(None)
) -> None:
    if not token:
        await websocket.close(code=1008)
        return

    try:
        token_payload = verify_access_token(token)
    except HTTPException:
        await websocket.close(code=1008)
        return

    user_id = token_payload["user_id"]
    await websocket.accept()
    _active_ws[user_id].append(websocket)

    conn = get_db_connection()
    pending = conn.execute(
        """
        SELECT id, sender_id, recipient_id, ciphertext, created_at
        FROM messages WHERE recipient_id = ?
        ORDER BY created_at ASC
        """,
        (user_id,),
    ).fetchall()
    conn.close()

    # Deliver pending messages
    for msg in pending:
        ct_b64 = base64.b64encode(msg["ciphertext"]).decode("utf-8")
        await websocket.send_json(
            {
                "type": "message",
                "message_id": msg["id"],
                "sender_id": msg["sender_id"],
                "recipient_id": msg["recipient_id"],
                "ciphertext_b64": ct_b64,
                "created_at": msg["created_at"],
            }
        )

    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")

            if action == "send":
                msg_id = data.get("message_id")
                recipient_id = data.get("recipient_id")
                ct_b64 = data.get("ciphertext_b64", "")

                try:
                    ct_bytes = base64.b64decode(ct_b64)
                except Exception:
                    await websocket.send_json(
                        {"type": "error", "detail": "Invalid ciphertext base64"}
                    )
                    continue

                if len(ct_bytes) > 65536:
                    await websocket.send_json(
                        {"type": "error", "detail": "Message oversize: exceeds 64KB limit"}
                    )
                    continue

                now = int(time.time())
                db_conn = get_db_connection()
                with db_conn:
                    db_conn.execute(
                        """
                        INSERT INTO messages (
                            id, sender_id, recipient_id, ciphertext, created_at, delivered
                        )
                        VALUES (?, ?, ?, ?, ?, 0)
                        """,
                        (msg_id, user_id, recipient_id, ct_bytes, now),
                    )
                db_conn.close()

                # Deliver to online recipient if connected
                if recipient_id in _active_ws and _active_ws[recipient_id]:
                    for r_ws in _active_ws[recipient_id]:
                        await r_ws.send_json(
                            {
                                "type": "message",
                                "message_id": msg_id,
                                "sender_id": user_id,
                                "recipient_id": recipient_id,
                                "ciphertext_b64": ct_b64,
                                "created_at": now,
                            }
                        )

            elif action == "ack":
                msg_id = data.get("message_id")
                db_conn = get_db_connection()
                with db_conn:
                    db_conn.execute(
                        "DELETE FROM messages WHERE id = ? AND recipient_id = ?",
                        (msg_id, user_id),
                    )
                db_conn.close()
                await websocket.send_json({"status": "ack_ok", "message_id": msg_id})

    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _active_ws[user_id]:
            _active_ws[user_id].remove(websocket)
            if not _active_ws[user_id]:
                del _active_ws[user_id]


class ConfirmTotpRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class CheckTotpRequest(BaseModel):
    user_id: str
    code: str


class ApproveDeviceRequest(BaseModel):
    user_id: str
    old_device_id: str
    new_device_id: str
    new_device_signing_pub: str
    new_device_encryption_pub: str
    approval_signature: str
    totp_code: str


_ph = PasswordHasher()


def _verify_user_code(user_id: str, code: str) -> bool:
    conn = get_db_connection()
    # 1. Try TOTP
    totp_row = conn.execute(
        "SELECT totp_secret FROM user_totp WHERE user_id = ?",
        (user_id,),
    ).fetchone()

    if totp_row:
        totp = pyotp.TOTP(totp_row["totp_secret"])
        if totp.verify(code, valid_window=1):
            conn.close()
            return True

    # 2. Try recovery codes
    now = int(time.time())
    rows = conn.execute(
        "SELECT id, code_hash, used FROM recovery_codes WHERE user_id = ?",
        (user_id,),
    ).fetchall()

    for row in rows:
        try:
            if _ph.verify(row["code_hash"], code):
                if row["used"] != 0:
                    conn.close()
                    raise HTTPException(
                        status_code=400,
                        detail="Recovery code already used",
                    )
                with conn:
                    conn.execute(
                        "UPDATE recovery_codes SET used = 1, used_at = ? WHERE id = ?",
                        (now, row["id"]),
                    )
                conn.close()
                return True
        except VerifyMismatchError:
            continue

    conn.close()
    return False


@app.post("/auth/totp/enroll")
def totp_enroll(authorization: str | None = Header(None)) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split(" ", 1)[1]
    payload = verify_access_token(token)
    user_id = payload["user_id"]

    secret = pyotp.random_base32()
    otpauth_url = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user_id, issuer_name="SecureChat"
    )

    now = int(time.time())
    recovery_codes = [secrets.token_hex(8) for _ in range(10)]

    conn = get_db_connection()
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO user_totp (user_id, totp_secret, confirmed, created_at)
            VALUES (?, ?, 0, ?)
            """,
            (user_id, secret, now),
        )
        # Invalidate old recovery codes
        conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
        for c in recovery_codes:
            chash = _ph.hash(c)
            conn.execute(
                """
                INSERT INTO recovery_codes (id, user_id, code_hash, used, created_at)
                VALUES (?, ?, ?, 0, ?)
                """,
                (secrets.token_hex(16), user_id, chash, now),
            )
    conn.close()

    return {
        "secret": secret,
        "otpauth_url": otpauth_url,
        "recovery_codes": recovery_codes,
    }


@app.post("/auth/totp/confirm")
def totp_confirm(
    req: ConfirmTotpRequest, authorization: str | None = Header(None)
) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split(" ", 1)[1]
    payload = verify_access_token(token)
    user_id = payload["user_id"]

    conn = get_db_connection()
    row = conn.execute(
        "SELECT totp_secret FROM user_totp WHERE user_id = ?",
        (user_id,),
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="TOTP not enrolled")

    totp = pyotp.TOTP(row["totp_secret"])
    if not totp.verify(req.code, valid_window=1):
        conn.close()
        raise HTTPException(status_code=400, detail="Wrong or invalid TOTP code")

    with conn:
        conn.execute("UPDATE user_totp SET confirmed = 1 WHERE user_id = ?", (user_id,))
    conn.close()

    return {"status": "ok"}


@app.post("/auth/totp/check")
def totp_check(req: CheckTotpRequest) -> dict[str, str]:
    if not _verify_user_code(req.user_id, req.code):
        raise HTTPException(status_code=400, detail="Invalid code")
    return {"status": "ok"}


@app.post("/devices/approve")
def approve_device(req: ApproveDeviceRequest) -> dict[str, str]:
    # 1. Verify old device exists
    conn = get_db_connection()
    old_dev = conn.execute(
        "SELECT device_signing_pub FROM devices WHERE id = ? AND user_id = ?",
        (req.old_device_id, req.user_id),
    ).fetchone()

    if not old_dev:
        conn.close()
        raise HTTPException(status_code=404, detail="Approval from unknown device")

    old_signing_pub = old_dev["device_signing_pub"]

    # 2. Verify TOTP or recovery code
    if not _verify_user_code(req.user_id, req.totp_code):
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid TOTP or recovery code")

    # 3. Canonical payload check
    payload_dict = {
        "user_id": req.user_id,
        "new_device_id": req.new_device_id,
        "new_device_signing_pub": req.new_device_signing_pub,
        "new_device_encryption_pub": req.new_device_encryption_pub,
    }
    payload_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")

    if not verify_ecdsa_signature(old_signing_pub, payload_bytes, req.approval_signature):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid approval signature")

    now = int(time.time())
    with conn:
        conn.execute(
            """
            INSERT INTO devices (
                id, user_id, device_signing_pub, device_encryption_pub, created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                req.new_device_id,
                req.user_id,
                req.new_device_signing_pub,
                req.new_device_encryption_pub,
                now,
            ),
        )
    conn.close()

    return {"status": "ok", "device_id": req.new_device_id}

