# SecureChat Wire Protocol Specification (v1)

## 1. Overview
SecureChat provides authenticated end-to-end encryption for 1:1 messaging using:
- **Symmetric Encryption**: AES-256-GCM with a fresh random 96-bit nonce per message.
- **Key Encapsulation**: RSA-2048 with OAEP and SHA-256 (wraps the 32-byte AES key).
- **Digital Signatures**: Ed25519 (64-byte signature over the envelope).
- **Authentication**: Authenticated Associated Data (AAD) binding sender, recipient, message ID, and timestamp.

---

## 2. Envelope Format (Version 0x01)

An encrypted envelope is formatted as follows:

| Field | Length | Description |
|---|---|---|
| `version` | 1 byte | Protocol version (`0x01`) |
| `sender_id_len` | 1 byte | Byte length of `sender_id` (N1) |
| `sender_id` | N1 bytes | UTF-8 sender identifier |
| `recipient_id_len` | 1 byte | Byte length of `recipient_id` (N2) |
| `recipient_id` | N2 bytes | UTF-8 recipient identifier |
| `message_id_len` | 1 byte | Byte length of `message_id` (N3) |
| `message_id` | N3 bytes | UTF-8 unique message identifier |
| `timestamp` | 8 bytes | Big-endian 64-bit integer (epoch seconds) |
| `wrapped_key` | 256 bytes | RSA-2048 OAEP-SHA256 encrypted 32-byte AES key |
| `nonce` | 12 bytes | 96-bit AES-GCM nonce |
| `mac` | 16 bytes | 128-bit AES-GCM authentication tag |
| `ciphertext_len` | 4 bytes | Big-endian 32-bit integer (length of ciphertext, N4) |
| `ciphertext` | N4 bytes | AES-256-GCM encrypted payload |
| `signature` | 64 bytes | Ed25519 digital signature over bytes [0 .. end of ciphertext] |

---

## 3. Associated Data (AAD)

For AES-GCM authenticated encryption, the Associated Data is canonically formed by concatenating:
`sender_id` + `":"` + `recipient_id` + `":"` + `message_id` + `":"` + `timestamp_str` (encoded as UTF-8).

---

## 4. Sealing Algorithm (`seal()`)

1. Generate a fresh 32-byte AES key: $K_{AES} \leftarrow \text{SecureRandom}(32)$.
2. Generate a fresh 12-byte nonce: $N \leftarrow \text{SecureRandom}(12)$.
3. Wrap $K_{AES}$ using recipient's RSA-2048 public key with OAEP-SHA256.
4. Construct AAD = `sender_id:recipient_id:message_id:timestamp`.
5. Encrypt plaintext using AES-256-GCM with $K_{AES}$, $N$, and AAD $\to$ `(ciphertext, mac)`.
6. Assemble envelope body: `version + header + wrapped_key + nonce + mac + ciphertext`.
7. Sign the envelope body using sender's Ed25519 private key $\to$ `signature` (64 bytes).
8. Append `signature` to the envelope body.

---

## 5. Opening Algorithm (`open()`)

1. Parse envelope fields and verify `version == 0x01`.
2. **Recipient check**: Verify `recipient_id == my_user_id`. Reject on mismatch.
3. **Clock skew check**: Verify $|timestamp - current\_time| \le 300\text{ seconds}$. Reject on deviation.
4. **Replay check**: Verify `message_id` has not been seen before. Reject on replay.
5. **Signature verification**: Verify 64-byte `signature` against envelope body [0 .. end of ciphertext] using sender's Ed25519 public key. Reject on invalid signature.
6. Record `message_id` in local replay guard cache.
7. **Key unwrapping**: Unwrap 32-byte AES key using recipient's RSA-2048 private key and OAEP-SHA256.
8. **Decryption**: Decrypt ciphertext using AES-256-GCM with unwrapped key, nonce, mac, and reconstructed AAD. Reject on authentication tag mismatch.
9. Return decrypted plaintext bytes.
