"""Main FastAPI application for SecureChat."""

import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/register")
def register(req: RegisterRequest) -> dict[str, str]:
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

        # Mark invite used
        conn.execute(
            "UPDATE invites SET used = 1, used_by = ?, used_at = ? WHERE code = ?",
            (req.user_id, now, req.invite_code),
        )

        # Create or update user
        conn.execute(
            "INSERT OR IGNORE INTO users (id, created_at) VALUES (?, ?)",
            (req.user_id, now),
        )

        # Register device
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
