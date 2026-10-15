#!/usr/bin/env python3
"""Interactive companion terminal client for testing SecureChat E2EE messages from phone."""

import asyncio
import base64
import io
import json
import os
import sqlite3
import struct
import sys
import time
from pathlib import Path

import httpx
import qrcode
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_PATH = Path(__file__).resolve().parent.parent / "server" / "securechat.db"
SERVER_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

PROTOCOL_VERSION = 0x01
KEYS_DIR = Path(__file__).resolve().parent / "companion_keys"
APK_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "app" / "build" / "app" / "outputs" / "flutter-apk"


def rsa_pub_to_hex(pub_key: rsa.RSAPublicKey) -> str:
    nums = pub_key.public_numbers()
    return f"{nums.n:x}:{nums.e:x}"


def load_or_generate_keys():
    KEYS_DIR.mkdir(exist_ok=True)
    rsa_path = KEYS_DIR / "alice_rsa.pem"
    ed_path = KEYS_DIR / "alice_ed.pem"
    dev_path = KEYS_DIR / "alice_dev.pem"

    if rsa_path.exists() and ed_path.exists() and dev_path.exists():
        with open(rsa_path, "rb") as f:
            rsa_priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(ed_path, "rb") as f:
            ed_priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(dev_path, "rb") as f:
            dev_priv = serialization.load_pem_private_key(f.read(), password=None)
    else:
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ed_priv = ed25519.Ed25519PrivateKey.generate()
        dev_priv = ec.generate_private_key(ec.SECP256R1())

        with open(rsa_path, "wb") as f:
            f.write(rsa_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(ed_path, "wb") as f:
            f.write(ed_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(dev_path, "wb") as f:
            f.write(dev_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    return rsa_priv, ed_priv, dev_priv


async def get_or_register_client(user_id: str = "alice", device_id: str = "PC-Companion"):
    rsa_priv, ed_priv, dev_priv = load_or_generate_keys()
    rsa_pub = rsa_priv.public_key()
    ed_pub = ed_priv.public_key()
    dev_pub = dev_priv.public_key()

    dev_pub_pem = dev_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Check database
    con = sqlite3.connect(DB_PATH, timeout=5.0)
    dev_row = con.execute(
        "SELECT device_signing_pub FROM devices WHERE user_id = ? AND id = ?",
        (user_id, device_id),
    ).fetchone()

    if not dev_row or dev_row[0].strip() != dev_pub_pem.strip():
        with con:
            con.execute("DELETE FROM devices WHERE user_id = ?", (user_id,))
            con.execute("DELETE FROM users WHERE id = ?", (user_id,))
        registered = False
    else:
        registered = True
    con.close()

    async with httpx.AsyncClient() as client:
        if not registered:
            from app.database import create_invite
            invite_code = create_invite(expires_in_seconds=86400)
            reg_resp = await client.post(
                f"{SERVER_URL}/register",
                json={
                    "invite_code": invite_code,
                    "user_id": user_id,
                    "device_id": device_id,
                    "device_signing_pub": dev_pub_pem,
                    "device_encryption_pub": rsa_pub_to_hex(rsa_pub),
                },
            )
            if reg_resp.status_code != 200:
                raise RuntimeError(f"Registration failed: {reg_resp.text}")

        # Challenge-response authentication
        chal_resp = await client.post(
            f"{SERVER_URL}/auth/challenge",
            json={"user_id": user_id, "device_id": device_id},
        )
        if chal_resp.status_code != 200:
            raise RuntimeError(f"Challenge failed: {chal_resp.text}")

        nonce = chal_resp.json()["nonce"]
        sig = dev_priv.sign(nonce.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        sig_b64 = base64.b64encode(sig).decode("utf-8")

        ver_resp = await client.post(
            f"{SERVER_URL}/auth/verify",
            json={
                "user_id": user_id,
                "device_id": device_id,
                "nonce": nonce,
                "signature": sig_b64,
            },
        )
        if ver_resp.status_code != 200:
            raise RuntimeError(f"Authentication failed: {ver_resp.text}")

        token = ver_resp.json()["access_token"]

    return {
        "user_id": user_id,
        "token": token,
        "rsa_priv": rsa_priv,
        "rsa_pub": rsa_pub,
        "ed_priv": ed_priv,
        "ed_pub": ed_pub,
    }


def generate_qr_artifacts(card_json: str):
    # 1. Print visual QR in console
    print("\n" + "=" * 60, flush=True)
    print("📲 SCAN THIS QR CODE WITH YOUR PHONE'S CAMERA:", flush=True)
    print("=" * 60, flush=True)
    try:
        qr = qrcode.QRCode(border=2)
        qr.add_data(card_json)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except Exception:
        pass
    print("=" * 60, flush=True)

    # 2. Save web browser viewable HTML QR code
    try:
        img = qrcode.make(card_json)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64_img = base64.b64encode(buf.getvalue()).decode("utf-8")

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SecureChat - Alice Contact QR</title>
    <style>
        body {{
            background: #0f172a;
            color: #f8fafc;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }}
        .card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 24px;
            padding: 32px;
            max-width: 440px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
        }}
        h2 {{
            color: #38bdf8;
            margin-top: 0;
            margin-bottom: 8px;
        }}
        p {{
            color: #94a3b8;
            font-size: 15px;
            margin-bottom: 24px;
        }}
        .qr-wrapper {{
            background: #ffffff;
            padding: 16px;
            border-radius: 16px;
            display: inline-block;
            margin-bottom: 20px;
        }}
        img {{
            width: 260px;
            height: 260px;
            display: block;
        }}
        .code-box {{
            background: #0f172a;
            padding: 12px;
            border-radius: 12px;
            font-family: monospace;
            font-size: 11px;
            word-break: break-all;
            color: #cbd5e1;
            text-align: left;
            max-height: 90px;
            overflow-y: auto;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h2>Scan to Add Contact</h2>
        <p>In the SecureChat app on your phone, tap the <b>QR Scanner</b> icon and point your camera here:</p>
        <div class="qr-wrapper">
            <img src="data:image/png;base64,{b64_img}" alt="Contact QR Code" />
        </div>
        <p style="font-size: 12px; margin-bottom: 8px;">Or copy fallback code:</p>
        <div class="code-box">{card_json}</div>
    </div>
</body>
</html>"""
        APK_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        html_path = APK_OUTPUT_DIR / "alice_qr.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"🌐 Or view in browser: http://192.168.29.122:8080/alice_qr.html", flush=True)
    except Exception as e:
        print(f"[Notice] Could not generate html QR: {e}", flush=True)


async def main():
    print("=" * 60, flush=True)
    print("  🚀 SecureChat Companion Client (Alice)", flush=True)
    print("=" * 60, flush=True)

    creds = await get_or_register_client("alice", "PC-Companion")
    ed_pub_bytes = creds["ed_pub"].public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    ed_pub_hex = ed_pub_bytes.hex()
    rsa_pub_hex = rsa_pub_to_hex(creds["rsa_pub"])

    contact_card = {
        "type": "contact_card",
        "user_id": "alice",
        "display_name": "Alice (PC)",
        "signing_pub": ed_pub_hex,
        "encryption_pub": rsa_pub_hex,
    }
    card_json = json.dumps(contact_card)

    generate_qr_artifacts(card_json)

    while True:
        try:
            ws_uri = f"{WS_URL}?token={creds['token']}"
            async with websockets.connect(ws_uri) as ws:
                print("\n[OK] Connected to SecureChat Server as 'alice'!", flush=True)
                print("Waiting for messages from your phone...\n", flush=True)

                async for raw_msg in ws:
                    data = json.loads(raw_msg)
                    msg_type = data.get("type")

                    if msg_type == "ack":
                        print(f"[ACK]: Message {data.get('message_id')} delivered.", flush=True)
                        continue

                    if msg_type == "message":
                        envelope_b64 = data.get("ciphertext_b64") or data.get("ciphertext")
                        if not envelope_b64:
                            continue

                        msg_id = data.get("message_id")
                        if msg_id:
                            # Acknowledge delivery
                            await ws.send(json.dumps({"action": "ack", "message_id": msg_id}))

                        try:
                            envelope_bytes = base64.b64decode(envelope_b64)
                            s_len = envelope_bytes[1]
                            s_id = envelope_bytes[2 : 2 + s_len].decode("utf-8")

                            body = envelope_bytes[:-64]
                            offset = 1 + 1 + s_len
                            r_len = body[offset]
                            offset += 1 + r_len
                            m_len = body[offset]
                            offset += 1 + m_len
                            timestamp = struct.unpack(">q", body[offset : offset + 8])[0]
                            offset += 8
                            wrapped_key = body[offset : offset + 256]
                            offset += 256
                            nonce = body[offset : offset + 12]
                            offset += 12
                            tag = body[offset : offset + 16]
                            offset += 16
                            ct_len = struct.unpack(">I", body[offset : offset + 4])[0]
                            offset += 4
                            ciphertext = body[offset : offset + ct_len]

                            # Unwrap AES key
                            aes_key = creds["rsa_priv"].decrypt(
                                wrapped_key,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None,
                                ),
                            )

                            # Decrypt AES-GCM
                            msg_id_in_env = body[2 + s_len + 1 + r_len : 2 + s_len + 1 + r_len + m_len].decode("utf-8")
                            aad = f"{s_id}:alice:{msg_id_in_env}:{timestamp}".encode("utf-8")
                            aesgcm = AESGCM(aes_key)
                            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext + tag, aad)
                            plaintext = plaintext_bytes.decode("utf-8")

                            print("\n" + "=" * 55, flush=True)
                            print(f"📩 [PHONE -> PC from '{s_id}']:\n{plaintext}", flush=True)
                            print("=" * 55 + "\n", flush=True)

                        except Exception as e:
                            print(f"[Notice] Failed to decrypt envelope: {e}", flush=True)

        except (websockets.exceptions.ConnectionClosed, ConnectionResetError, OSError) as e:
            print(f"[Notice] WebSocket disconnected ({e}). Reconnecting in 2s...", flush=True)
            await asyncio.sleep(2)
            try:
                creds = await get_or_register_client("alice", "PC-Companion")
            except Exception:
                pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting companion.")
