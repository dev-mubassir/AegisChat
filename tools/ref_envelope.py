"""Reference implementation of SecureChat Protocol v1 message envelope.

Uses python-cryptography library to independently seal and open envelopes,
verifying complete interoperability with the Dart/Flutter client implementation.
"""

import os
import struct
import time
from typing import NamedTuple, Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SealedEnvelope(NamedTuple):
    version: int
    sender_id: str
    recipient_id: str
    message_id: str
    timestamp: int
    wrapped_key: bytes
    nonce: bytes
    mac: bytes
    ciphertext: bytes
    signature: bytes
    raw_envelope: bytes


def build_aad(sender_id: str, recipient_id: str, message_id: str, timestamp: int) -> bytes:
    """Builds canonical Associated Data string as defined in PROTOCOL.md."""
    return f"{sender_id}:{recipient_id}:{message_id}:{timestamp}".encode("utf-8")


def rsa_key_from_components(
    n: int,
    e: int,
    d: Optional[int] = None,
    p: Optional[int] = None,
    q: Optional[int] = None,
):
    """Reconstructs an RSA public or private key from mathematical components."""
    pub_numbers = rsa.RSAPublicNumbers(e, n)
    if d is not None and p is not None and q is not None:
        dmp1 = d % (p - 1)
        dmq1 = d % (q - 1)
        iqmp = pow(q, -1, p)
        priv_numbers = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub_numbers)
        return priv_numbers.private_key()
    return pub_numbers.public_key()


def seal(
    sender_id: str,
    recipient_id: str,
    message_id: str,
    timestamp: int,
    plaintext: bytes,
    recipient_rsa_public_key: rsa.RSAPublicKey,
    sender_signing_key: ed25519.Ed25519PrivateKey,
    aes_key: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> bytes:
    """Seals plaintext into a protocol v1 envelope byte array."""
    if aes_key is None:
        aes_key = os.urandom(32)
    if nonce is None:
        nonce = os.urandom(12)

    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")

    # 1. Wrap AES key using RSA-2048 OAEP-SHA256
    wrapped_key = recipient_rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(wrapped_key) != 256:
        raise ValueError(f"Expected 256-byte wrapped key, got {len(wrapped_key)}")

    # 2. Associated data
    aad = build_aad(sender_id, recipient_id, message_id, timestamp)

    # 3. Encrypt plaintext with AES-256-GCM
    aesgcm = AESGCM(aes_key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext = ct_and_tag[:-16]
    mac = ct_and_tag[-16:]

    # 4. Serialize envelope body
    s_bytes = sender_id.encode("utf-8")
    r_bytes = recipient_id.encode("utf-8")
    m_bytes = message_id.encode("utf-8")

    body = bytearray()
    body.append(0x01)  # Version

    body.append(len(s_bytes))
    body.extend(s_bytes)

    body.append(len(r_bytes))
    body.extend(r_bytes)

    body.append(len(m_bytes))
    body.extend(m_bytes)

    body.extend(struct.pack(">q", timestamp))
    body.extend(wrapped_key)
    body.extend(nonce)
    body.extend(mac)
    body.extend(struct.pack(">I", len(ciphertext)))
    body.extend(ciphertext)

    # 5. Sign envelope body with Ed25519
    signature = sender_signing_key.sign(bytes(body))
    if len(signature) != 64:
        raise ValueError(f"Expected 64-byte Ed25519 signature, got {len(signature)}")

    return bytes(body) + signature


def parse_envelope(envelope_bytes: bytes) -> SealedEnvelope:
    """Parses raw envelope bytes into structured SealedEnvelope."""
    min_len = 1 + 1 + 1 + 1 + 8 + 256 + 12 + 16 + 4 + 64
    if len(envelope_bytes) < min_len:
        raise ValueError("Envelope too short")

    offset = 0
    version = envelope_bytes[offset]
    offset += 1
    if version != 0x01:
        raise ValueError(f"Unsupported protocol version: {version}")

    s_len = envelope_bytes[offset]
    offset += 1
    sender_id = envelope_bytes[offset : offset + s_len].decode("utf-8")
    offset += s_len

    r_len = envelope_bytes[offset]
    offset += 1
    recipient_id = envelope_bytes[offset : offset + r_len].decode("utf-8")
    offset += r_len

    m_len = envelope_bytes[offset]
    offset += 1
    message_id = envelope_bytes[offset : offset + m_len].decode("utf-8")
    offset += m_len

    (timestamp,) = struct.unpack(">q", envelope_bytes[offset : offset + 8])
    offset += 8

    wrapped_key = envelope_bytes[offset : offset + 256]
    offset += 256

    nonce = envelope_bytes[offset : offset + 12]
    offset += 12

    mac = envelope_bytes[offset : offset + 16]
    offset += 16

    (ct_len,) = struct.unpack(">I", envelope_bytes[offset : offset + 4])
    offset += 4

    if offset + ct_len + 64 != len(envelope_bytes):
        raise ValueError("Envelope length mismatch")

    ciphertext = envelope_bytes[offset : offset + ct_len]
    offset += ct_len

    signature = envelope_bytes[offset : offset + 64]

    return SealedEnvelope(
        version=version,
        sender_id=sender_id,
        recipient_id=recipient_id,
        message_id=message_id,
        timestamp=timestamp,
        wrapped_key=wrapped_key,
        nonce=nonce,
        mac=mac,
        ciphertext=ciphertext,
        signature=signature,
        raw_envelope=envelope_bytes,
    )


def open_envelope(
    envelope_bytes: bytes,
    expected_recipient_id: str,
    sender_signing_public_key: ed25519.Ed25519PublicKey,
    recipient_rsa_private_key: rsa.RSAPrivateKey,
    seen_message_ids: Optional[set] = None,
    current_time: Optional[int] = None,
    max_clock_skew: int = 300,
) -> bytes:
    """Verifies and decrypts a protocol v1 envelope."""
    parsed = parse_envelope(envelope_bytes)

    # 1. Recipient check
    if parsed.recipient_id != expected_recipient_id:
        raise ValueError(
            f"Recipient mismatch: expected {expected_recipient_id}, got {parsed.recipient_id}"
        )

    # 2. Clock skew check
    if current_time is None:
        current_time = int(time.time())
    if abs(parsed.timestamp - current_time) > max_clock_skew:
        raise ValueError(f"Clock skew exceeded: diff {abs(parsed.timestamp - current_time)}s")

    # 3. Replay check
    if seen_message_ids is not None:
        if parsed.message_id in seen_message_ids:
            raise ValueError(f"Replay detected for message: {parsed.message_id}")

    # 4. Verify Ed25519 signature over envelope body [0 .. end of ciphertext]
    body = envelope_bytes[:-64]
    try:
        sender_signing_public_key.verify(parsed.signature, body)
    except InvalidSignature as e:
        raise ValueError("Invalid digital signature") from e

    if seen_message_ids is not None:
        seen_message_ids.add(parsed.message_id)

    # 5. Unwrap AES key using RSA-2048 OAEP-SHA256
    try:
        aes_key = recipient_rsa_private_key.decrypt(
            parsed.wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise ValueError(f"Failed to unwrap AES key: {e}") from e

    # 6. Decrypt ciphertext with AES-256-GCM
    aad = build_aad(parsed.sender_id, parsed.recipient_id, parsed.message_id, parsed.timestamp)
    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(parsed.nonce, parsed.ciphertext + parsed.mac, aad)
        return plaintext
    except InvalidTag as e:
        raise ValueError("AES-GCM decryption / tag verification failed") from e
