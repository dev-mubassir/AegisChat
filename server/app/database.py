"""Database models and SQLite connection for SecureChat server."""

import os
import secrets
import sqlite3
import time
from pathlib import Path

DEFAULT_DB_PATH = str(Path(__file__).resolve().parent.parent / "securechat.db")


def get_db_path() -> str:
    return os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)


def get_db_connection(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or get_db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str | None = None) -> None:
    conn = get_db_connection(db_path)
    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                device_signing_pub TEXT NOT NULL,
                device_encryption_pub TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS invites (
                code TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                used_by TEXT,
                used_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0,
                delivered_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                family_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_challenges (
                nonce TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS user_totp (
                user_id TEXT PRIMARY KEY,
                totp_secret TEXT NOT NULL,
                confirmed INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS recovery_codes (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL,
                used_at INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
            CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, delivered);
            CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens(token_hash);
            CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id, used);
            """
        )
    conn.close()


def create_invite(db_path: str | None = None, expires_in_seconds: int = 86400) -> str:
    init_db(db_path)
    code = secrets.token_urlsafe(24)
    now = int(time.time())
    expires_at = now + expires_in_seconds
    conn = get_db_connection(db_path)
    with conn:
        conn.execute(
            "INSERT INTO invites (code, created_at, expires_at, used) VALUES (?, ?, ?, 0)",
            (code, now, expires_at),
        )
    conn.close()
    return code


def purge_expired_messages(
    db_path: str | None = None, max_age_seconds: int = 30 * 86400
) -> int:
    init_db(db_path)
    now = int(time.time())
    cutoff = now - max_age_seconds
    conn = get_db_connection(db_path)
    with conn:
        cursor = conn.execute(
            "DELETE FROM messages WHERE created_at < ?",
            (cutoff,),
        )
        count = cursor.rowcount
    conn.close()
    return count

