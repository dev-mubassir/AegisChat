# Security Policy

At AegisChat, security is not an afterthought or an add-on—it is the foundational premise of our architecture. We operate on a strict **Zero-Knowledge**, **Zero-Trust**, and **Hardware-Backed End-to-End Encryption** model.

We take the security of our cryptographic protocols, mobile implementation, and backend relay infrastructure seriously. We welcome responsible security researchers and bug bounty hunters to audit our codebase and report any potential vulnerabilities.

---

## Supported Versions

Only the latest release and the current active development branch (`master`) receive active security updates and cryptographic patches:

| Version | Supported          | Cryptographic Envelope |
| ------- | ------------------ | ---------------------- |
| 1.0.x   | :white_check_mark: | AES-256-GCM + Ed25519  |
| < 1.0   | :x:                | Deprecated / Prototype |

---

## Cryptographic Guarantees & Invariants

When evaluating the security posture of AegisChat, the following invariants are enforced by design:

1. **Zero Server Plaintext**: The backend relay server never receives, stores, or processes unencrypted message payloads, ephemeral symmetric keys, or private key material.
2. **Hardware-Backed Keystores**: Private identity keys (Ed25519) and encryption keypairs are generated and protected within hardware secure elements (Android Keymaster/StrongBox / iOS Secure Enclave).
3. **Double-Ratchet Forward & Post-Compromise Secrecy**: Every conversation turn ratchets message keys using HKDF-SHA256, ensuring past and future communications remain safe even under temporary device key compromise.
4. **AAD Protocol Binding**: All ciphertexts are authenticated using Additional Authenticated Data (`sender_pub || recipient_pub || seq_no || timestamp`), preventing ciphertext tampering, replay attacks, or recipient redirection.
5. **Argon2id Master Vault**: Local SQLite message caches and persistent keystores are encrypted with Argon2id-derived key hierarchies with zero plaintext exposure to memory dumps.

---

## Reporting a Vulnerability

If you discover a security vulnerability, cryptographic weakness, replay vulnerability, or leak in AegisChat, please do **NOT** open a public GitHub issue.

Please report vulnerabilities through one of the following channels:

- **GitHub Private Vulnerability Reporting**: Use the [Security Advisory Reporting](https://github.com/dev-mubassir/AegisChat/security/advisories/new) feature directly on this repository.
- **Security Contact**: Contact the repository maintainers via security advisory or maintainer profile at [dev-mubassir](https://github.com/dev-mubassir).

### Please include in your report:
- **Type of issue**: (e.g., Cryptographic flaw, Key Exchange bypass, Replay attack, Memory leak of sensitive material, Backend relay privilege escalation).
- **Component**: (e.g., Flutter App, Android Keystore bridge, WebSocket Relay server, Double Ratchet implementation, Companion CLI).
- **Steps to reproduce**: Detailed step-by-step instructions or proof-of-concept (PoC) code.
- **Impact assessment**: What attack vector does this open, and what are the prerequisites (e.g., MITM network access, physical device access, compromised server)?

---

## Disclosure & Remediation Timeline

We adhere to a standard 90-day responsible disclosure timeline:

- **Initial Acknowledgment**: Within 48 hours of receipt.
- **Triage & Reproduction**: Within 7 business days.
- **Patch Development & Testing**: Prioritized based on CVSS severity (critical vulnerabilities patched within 14 days).
- **Public Advisory & Release**: Coordinated release with CVE assignment and security advisory credits.

---

## Safe Harbor

We will not initiate legal action against researchers who:
- Make a good faith effort to avoid privacy violations, data destruction, and interruption of services.
- Give us reasonable time to remediate vulnerabilities before public disclosure.
- Do not exploit a vulnerability beyond what is strictly necessary to establish proof-of-concept.
