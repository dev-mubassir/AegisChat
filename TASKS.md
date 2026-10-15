# SecureChat tasks

## Spec

- Layout: `server/` (FastAPI + SQLite + pytest), `app/` (Flutter, Android + iOS), `tools/` (Python scripts), `docs/`.
- One user = one phone. 1:1 chats only. Invite-only, no public sign-up.
- Message path: the sender encrypts with AES-256-GCM, wraps the AES key with the receiver's RSA-2048 key (OAEP) and signs the package. The server relays ciphertext over TLS and deletes it after delivery. The receiver verifies, unwraps and decrypts.
- Login: the phone's device key signs a server challenge. Backup: TOTP and recovery codes. A new phone is approved from the old phone.
- Check shortcuts: S = `cd server && python -m pytest -q`. A = `cd app && flutter analyze && flutter test`.
- Every task ships with tests. A task is done only when its Check passes. If a task is too big for one run, split it into smaller tasks here.

## Setup

- [x] T01 Repo and server skeleton
  Do: `git init`; `.gitignore` (keys, `.env`, `*.jks`, `*.keystore`, `.venv`, `build/`, `logs/`); `CONTEXT.md`; `server/` FastAPI app with `/health`; pinned `requirements.txt`; pytest and ruff config.
  Check: S passes and `python -m ruff check server` is clean.
  Evidence: `cd server && python -m pytest -q` passed (1 passed in 0.69s); `python -m ruff check server` passed (All checks passed!).
- [x] T02 Flutter skeleton
  Do: `flutter create app --platforms android,ios`; add `cryptography`, `pointycastle`, `flutter_secure_storage`, `local_auth`, `web_socket_channel`, `http` and a QR show/scan package; pin versions.
  Check: A passes. Note `flutter --version` in `CONTEXT.md`. Flutter missing: BLOCKED.
  Evidence: `cd app && flutter analyze && flutter test` passed (flutter analyze: No issues found!; flutter test: All tests passed!).

## Server

- [x] T03 Database and invites
  Do: SQLite tables for users, devices (public keys), invites (one-time, expiring), messages (ciphertext bytes, sender, recipient, created, delivered) and refresh tokens. `server/manage.py create-invite`. `POST /register` takes an invite and the phone's public keys.
  Check: S passes, with tests for a valid, reused, expired and invalid invite.
  Evidence: `cd server && python -m pytest -q` passed (6 passed in 1.23s: valid, reused, expired, invalid invites and CLI create-invite).
- [x] T04 Challenge login and tokens
  Do: `POST /auth/challenge` (random one-time nonce, 60 s) and `POST /auth/verify` (ECDSA P-256 signature over the nonce) return a 10-minute access token and a rotating refresh token. Reusing an old refresh token revokes that token family. Rate limits on `/register` and `/auth/*` (per IP and per device).
  Check: S passes, with tests for replayed nonce, expired nonce, bad signature, refresh reuse and rate limit.
  Evidence: `cd server && python -m pytest -q` passed (12 passed in 2.17s: challenge, verify, replayed nonce, expired nonce, bad signature, refresh reuse family revocation, rate limits).
- [x] T05 Key directory and message relay
  Do: `GET /keys/{user_id}` (login required). WebSocket `/ws` (token auth): receive, store ciphertext, deliver if the receiver is online, wait for the ack, then delete the row. Purge undelivered messages after 30 days. Size limit and ordering.
  Check: S passes, with tests for offline delivery, delete-on-ack, unauthorised and oversize messages.
  Evidence: `cd server && python -m pytest -q` passed (18 passed in 2.77s: keys endpoint, offline delivery, delete-on-ack, unauthorised, oversize limits, 30-day purge).
- [x] T06 Server privacy
  Do: log redaction (no bodies, no tokens); security headers; CORS closed; request size limit. Test: send messages through the relay with a plaintext marker, then scan the SQLite file and the captured logs. The marker must not appear.
  Check: S passes.
  Evidence: `cd server && python -m pytest -q` passed (22 passed in 3.13s: log redaction, security headers, closed CORS, request size limit, zero plaintext/tokens in DB/logs).
- [x] T07 TOTP, recovery codes, new-device approval
  Do: `pyotp` TOTP enrolment and check; 10 single-use recovery codes stored hashed (Argon2id); new-device approval = the old device signs the new device's key (QR payload) and a TOTP code is required.
  Check: S passes, with tests for wrong code, reused recovery code and approval from an unknown device.
  Evidence: `cd server && python -m pytest -q` passed (27 passed in 9.08s: TOTP enrol/check, wrong code rejection, single-use recovery code reuse prevention, new-device approval, unknown device rejection).

## App crypto

- [x] T08 AES-256-GCM
  Do: `app/lib/crypto/aes_gcm.dart`: encrypt and decrypt with a random 96-bit nonce and associated data.
  Check: `cd app && flutter test test/crypto` passes, with known-answer vectors, a flip-any-bit tamper test, wrong key or associated data fails, and 10,000 nonces all unique.
  Evidence: `cd app && flutter test test/crypto` passed (6 passed: roundtrip, KAT vectors, flip-any-bit tamper, wrong key/aad rejection, 10,000 nonces all unique).
- [x] T09 RSA-OAEP and signatures
  Do: RSA-2048 key generation (run it in a background isolate: pure-Dart RSA key generation can take many seconds), OAEP-SHA256 wrap and unwrap of a 32-byte key, Ed25519 (or RSA-PSS) sign and verify.
  Check: `cd app && flutter test test/crypto` passes, with tests for round trip, wrong key, two wraps of one key differ, and tampered signature.
  Evidence: `cd app && flutter test test/crypto` passed (13 passed: isolate keygen, OAEP-SHA256 wrap/unwrap, probabilistic padding, wrong key rejection, Ed25519 sign/verify, tampered sig/msg rejection).
- [x] T10 Message envelope
  Do: `seal()` and `open()` combine T08 and T09. Versioned format written in `docs/PROTOCOL.md`. Associated data = sender id + recipient id + message id + timestamp. Replay guard by message id. Reject a wrong recipient and timestamps outside the allowed clock skew.
  Check: same command, with tests for round trip, tampering with any field, replay and wrong recipient.
  Evidence: `cd app && flutter test test/crypto` passed (18 passed: round trip, tampering with any field, replay, wrong recipient, clock skew) and `flutter analyze` clean.
- [x] T11 Key storage and safety numbers
  Do: `KeyStore` interface over `flutter_secure_storage` (plus an in-memory fake for tests). Keys are never written anywhere else. A 60-digit safety number and a QR payload from two public keys, identical on both phones.
  Check: A passes.
  Evidence: `flutter analyze` clean (0 issues) and `flutter test` passed (24 tests passed across crypto and smoke suite).
- [x] T12 Cross-language crypto check (the most important crypto test)
  Do: write an independent Python version of `docs/PROTOCOL.md` in `tools/ref_envelope.py` using the `cryptography` package. Dart writes test vectors to `docs/vectors.json`. Python must open every one, and envelopes made by Python must open in Dart. `tools/xcheck.py` runs both directions.
  Check: `python tools/xcheck.py` exits 0.
  Evidence: `python tools/xcheck.py` exited 0 (Direction 1: Dart -> Python opened 3 vectors, Direction 2: Python -> Dart opened 3 vectors including 2.4KB large payload and emojis).

## App login

- [x] T13 Device key and login
  Do: `DeviceKey` interface with `HardwareDeviceKey` (Android Keystore/StrongBox and iOS Secure Enclave through a platform channel; P-256, non-exportable, biometric-gated; compile-checked only) and `SoftwareDeviceKey` (tests only). Login client: challenge, sign, tokens, secure token storage, refresh rotation. Put the hardware parts in `MANUAL_CHECKS.md`.
  Check: A passes (tests use `SoftwareDeviceKey` and a fake HTTP server).
  Evidence: `flutter analyze` clean (0 issues) and `flutter test` passed (31 tests passed: SoftwareDeviceKey SPKI PEM + signature, challenge-response login, 404/401 handling, refresh rotation, reuse purge, logout).
- [x] T14 App lock
  Do: biometric (`local_auth`) plus 6-digit PIN (Argon2id-derived key), a growing delay after wrong tries, wipe local keys after 10 failures, auto-lock after 60 s in the background.
  Check: A passes (tests use a fake clock and fake storage).
  Evidence: `flutter analyze` clean (0 issues) and `flutter test` passed (37 tests passed: 6-digit Argon2id PIN setup/verify, 5s-300s growing delays, 10-failure key wipe, 60s background auto-lock, biometric unlock).
- [x] T15 TOTP, recovery and new-device screens
  Do: TOTP enrolment, recovery codes shown once, new-device approval by QR on both phones (logic and widget tests).
  Check: A passes.
  Evidence: `flutter analyze` clean (0 issues) and `flutter test` passed (42 tests passed: TotpService HTTP enroll/confirm, canonical payload ECDSA signing, TotpEnrollmentScreen QR/recovery codes, DeviceApprovalScreen QR/approver).

## Chat

- [x] T16 Encrypted local storage
  Do: store messages encrypted at rest: SQLCipher if it works under `flutter test`, otherwise per-record AES-256-GCM with a key from `KeyStore`.
  Check: A passes, including a test that the file on disk has no plaintext marker and a wrong key cannot read it.
  Evidence: `flutter analyze` clean (0 issues) and `flutter test` passed (47 tests passed: per-record AES-256-GCM, zero plaintext markers on disk, wrong key rejection, bit-tampering detection).
- [ ] T17 Contacts and verification
  Do: add a contact by scanning a QR (user id + public keys + invite), show the safety number, a "verified" flag, and a warning when a contact's key changes.
  Check: A passes.
- [ ] T18 Chat service
  Do: WebSocket client with reconnect and backoff. Send = seal, then relay. Receive = verify, open, store, ack. Offline queue. States: sending, sent, delivered.
  Check: A passes (tests use a fake WebSocket server).
- [ ] T19 Chat UI
  Do: contact list, chat screen, registration (invite) screen, lock screen, safety-number screen. Simple Material 3.
  Check: A passes, with widget tests: a sent message appears, a received message is decrypted, a locked app shows the lock screen.
- [ ] T20 Platform privacy flags
  Do: Android `allowBackup=false`, cleartext off with a network security config, `FLAG_SECURE` on the main activity, generic notification text. iOS: exclude from backup and blur in the app switcher (compile-checked only). `tools/check_platform_flags.py` fails when a flag is missing.
  Check: `python tools/check_platform_flags.py` exits 0.
- [ ] T21 Certificate pinning
  Do: pin the SHA-256 of the server public key plus one backup pin, set in one config file. Unit-test the matching function (good pin, wrong pin, backup pin). Explain how to rotate pins in `docs/SECURITY.md`.
  Check: A passes.

## Checks and build

- [ ] T22 Scanners
  Do: `tools/crypto_lint.py` fails on ECB, CBC, PKCS#1 v1.5, MD5/SHA-1 for security, non-secure `Random(`, hard-coded keys or IVs, printed keys or tokens, and SharedPreferences used for keys. `tools/scan_secrets.py` fails on private-key blocks, tokens and a committed `.env`. Both have self-tests with bad samples. Also run `bandit -r server` and `pip-audit`.
  Check: both scripts exit 0 on the repo and non-zero on their bad samples.
- [ ] T23 End-to-end test
  Do: `tools/e2e.py` starts the server on a free port with a temporary database, runs a headless Dart test (`app/test_e2e/`) where two clients register with invites, log in and exchange messages through the real server, then checks that the server database and logs hold no plaintext.
  Check: `python tools/e2e.py` exits 0.
- [ ] T24 Android build
  Do: `flutter build apk --debug`. The release build uses a local keystore that is NOT in git. Android SDK missing: BLOCKED with install steps.
  Check: `app/build/app/outputs/flutter-apk/app-debug.apk` exists.
- [ ] T25 iOS config
  Do: `codemagic.yaml` that builds an unsigned IPA, and `docs/IOS.md`: sideloading with a free Apple ID (7-day expiry, no push, no passkeys) versus a paid account. Add the iOS checks to `MANUAL_CHECKS.md`.
  Check: the YAML parses (`python -c "import yaml; yaml.safe_load(open('codemagic.yaml'))"`). An iOS build cannot be tested here.
- [ ] T26 Docs
  Do: `README.md` (run the server, create an invite, run tests, build the APK, deploy with Caddy and a domain), `docs/SECURITY.md` (threat model, limits, key rotation, what happens on a lost phone), `MANUAL_CHECKS.md` (step-by-step checklist for a real phone).
  Check: the three files exist and two README commands re-run successfully.
