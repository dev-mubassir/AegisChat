# SecureChat Security Architecture & Operations Guide

## 1. Threat Model & Security Architecture

SecureChat is designed for zero-trust, confidential end-to-end encrypted messaging between authenticated mobile clients via an untrusted relay server.

### Core Cryptographic Invariants 
- **Message Confidentiality & Authenticity**: AES-256-GCM authenticated encryption. Each message uses a fresh 96-bit CSPRNG nonce (`Random.secure()`). Associated data (AAD) binds `sender_id`, `recipient_id`, `message_id`, and Unix timestamp. Tampering with any byte or metadata immediately fails GCM authentication tag verification.
- **Key Encapsulation**: Ephemeral 256-bit AES symmetric keys are wrapped using RSA-2048 with OAEP padding and SHA-256 (`RSAEngine` + `OAEPEncoding.withCustomDigest(() => SHA256Digest())`).
- **Cryptographic Signatures & Non-Repudiation**: Ed25519 digital signatures. The entire message envelope (version, IDs, timestamp, wrapped key, ciphertext) is signed by the sender's private signing key and verified before decryption.
- **Zero Plaintext Storage**: The relay server never possesses user private keys or session keys. Messages are stored only as opaque encrypted blobs and permanently deleted immediately upon delivery acknowledgement (`ack`).
- **Encrypted Local Storage**: Local message store on mobile device is encrypted at rest per-record using AES-256-GCM with a 256-bit key stored in hardware-backed keystore (`flutter_secure_storage`).

---

## 2. Certificate Pinning & Key Rotation

SecureChat enforces TLS 1.3 certificate pinning to prevent Man-in-the-Middle (MITM) attacks by rogue Certificate Authorities or corporate TLS proxies.

### Pinning Configuration (`app/lib/network/cert_pinning.dart`)
Pins are computed as the SHA-256 hash of the server's DER certificate bytes:
$$\text{Pin} = \text{"sha256/"} + \text{Base64}(\text{SHA-256}(\text{Certificate DER}))$$

The client configuration specifies:
1. **Primary Pin**: Matches the currently active production server certificate.
2. **Backup Pin**: Matches a standby offline certificate/keypair to ensure business continuity if the primary certificate expires or needs emergency revocation.

### Step-by-Step Pin Rotation Procedure
Never deploy a new server certificate without an active backup pin already deployed to user devices, as this will lock users out of the server.

1. **Step 1: Generate New Standby Keypair and Certificate**
   Generate a new TLS private key and CSR/certificate for your domain:
   ```bash
   openssl req -new -newkey rsa:2048 -nodes -keyout securechat_next.key -out securechat_next.csr
   # Obtain or self-sign the new certificate: securechat_next.crt
   ```
2. **Step 2: Extract SHA-256 Pin**
   ```bash
   openssl x509 -in securechat_next.crt -outform der | openssl dgst -sha256 -binary | openssl base64
   ```
3. **Step 3: Update Client Backup Pin**
   In `app/lib/network/cert_pinning.dart`, set `backupPin` to the newly computed hash:
   ```dart
   static const PinningConfig defaultConfig = PinningConfig(
     primaryPin: 'sha256/<current_active_pin>=',
     backupPin: 'sha256/<newly_computed_pin>=',
   );
   ```
4. **Step 4: Release Client Update**
   Deploy the client app update to all devices. Allow time for users to update.
5. **Step 5: Activate New Certificate on Server**
   Deploy `securechat_next.crt` and `securechat_next.key` to the production server (e.g. Caddy / reverse proxy). Because the client recognizes the backup pin, connections succeed immediately without disruption.
6. **Step 6: Promote Backup Pin in Next Release**
   In the following app release:
   - Promote `backupPin` to `primaryPin`.
   - Generate a fresh offline standby certificate and place its pin in `backupPin`.

---

## 3. What Happens on a Lost or Stolen Phone

### Device-Side Protection
- **Argon2id Local App Lock**: The app requires a 6-digit PIN. The PIN is hashed using Argon2id ($m=4\text{MB}, t=2, p=1$) with a 16-byte random salt.
- **Progressive Delay Backoff**:
  - 1–3 failed attempts: No delay.
  - 4 failed attempts: 5-second cooldown.
  - 5 failed attempts: 15-second cooldown.
  - 6 failed attempts: 30-second cooldown.
  - 7 failed attempts: 60-second cooldown.
  - 8 failed attempts: 120-second cooldown.
  - 9 failed attempts: 300-second cooldown.
- **10-Failure Automatic Key Wipe**: If 10 consecutive incorrect PIN attempts are made, `AppLockManager` triggers `deleteAll()` on the secure keystore. All local cryptographic keys, authentication tokens, and cached messages are permanently destroyed.
- **60-Second Background Auto-Lock**: When the application enters the background for $\ge 60$ seconds, it automatically locks and requires PIN or biometric re-authentication.
- **Platform Hardening**:
  - `allowBackup="false"` prevents ADB backups or cloud extraction of app data.
  - `FLAG_SECURE` prevents screenshots, screen recording, and task switcher snapshots.

### Server-Side Revocation
- **Revoke Device**: If a phone is lost or compromised, the user logs in from an existing approved device and calls `POST /auth/device/revoke` to invalidate the lost device's refresh token and access tokens.
- **Relay Messages**: Undelivered messages for the compromised device can be deleted from the relay server, preventing retrieval upon device theft.

---

## 4. Known Limitations & Threat Boundaries

1. **Metadata Visibility**: The relay server observes metadata (sender ID, recipient ID, message timestamp, message size, and client IP addresses). End-to-end encryption protects the message payload and content, but not communication graph metadata. Use a VPN or Tor for network metadata privacy.
2. **Unlocked Stolen Phone**: If an adversary physically seizes an unlocked device while the app is active and foregrounded, data on screen is accessible. The 60-second background auto-lock and manual lock mitigate this risk once foreground focus is lost.
3. **Device Compromise (Root/Jailbreak)**: Advanced spyware or OS-level compromise (kernel exploit, memory scraper) can bypass userspace security boundaries. Hardware-backed security key isolation (`HardwareDeviceKey`) minimizes key extraction risk on supported devices.
4. **Independent Audit**: This codebase has been rigorously designed to cryptographic specifications, but has not yet undergone a third-party commercial penetration test or formal cryptographic verification.
