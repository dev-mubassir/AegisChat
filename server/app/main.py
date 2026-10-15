"""Main FastAPI application for SecureChat."""

import secrets
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from app.auth import (
    check_rate_limit,
    create_access_token,
    issue_refresh_token,
    rotate_refresh_token,
    verify_ecdsa_signature,
)
from app.database import get_db_connection, init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    init_db()
    yield


app = FastAPI(title="SecureChat Server", lifespan=lifespan)


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
            INSERT INTO devices (id, user_id, device_signing_pub, device_encryption_pub, created_at)
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
