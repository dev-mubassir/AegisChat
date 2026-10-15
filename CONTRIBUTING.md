# Contributing to AegisChat

Thank you for your interest in contributing to AegisChat! Because AegisChat is a zero-trust, end-to-end encrypted security project, all contributions must adhere to strict cryptographic and architectural standards.

---

## 1. Development Prerequisites

* **Flutter SDK**: 3.47+ (Dart 3.13+)
* **Python**: 3.10+ (with `pip` and `venv`)
* **Java**: OpenJDK 17 LTS (HotSpot)
* **Android SDK**: API 34+, Build-Tools 36.0.0+

---

## 2. Project Layout

```text
├── app/                  # Mobile Client (Flutter)
│   ├── lib/
│   │   ├── auth/         # Device key, Argon2id AppLock, Challenge-response
│   │   ├── chat/         # WebSocket chat service and offline queues
│   │   ├── contacts/     # ContactManager, SafetyNumber, QR payload parser
│   │   ├── crypto/       # AES-GCM, RSA-OAEP, Ed25519 MessageEnvelope
│   │   ├── storage/      # EncryptedMessageStore (at-rest AES-256-GCM)
│   │   └── ui/           # ChatScreen, ContactsScreen, QrScanScreen, LockScreen
│   └── test/             # 65 comprehensive unit and widget tests
├── server/               # Zero-Knowledge Relay Backend (FastAPI)
│   ├── app/              # SQLite database, Auth, WebSocket relay, Invites
│   └── tests/            # 27 server test cases
├── tools/                # Security verification scripts & companion CLI
│   ├── check_platform_flags.py  # Automated Android/iOS privacy compliance
│   └── companion_client.py      # Interactive PC companion test client
├── ARCHITECTURE.md       # Cryptographic specification & threat model
└── README.md             # Project documentation & quick start
```

---

## 3. Running Test Suites

All tests must pass before submitting code changes:

### Flutter Test Suite (65/65 tests)
```bash
cd app
flutter test
```

### Static Analysis (0 issues)
```bash
cd app
flutter analyze
```

### Platform Privacy Compliance Verification
```bash
python tools/check_platform_flags.py
```

### Backend Relay Test Suite (27/27 tests)
```bash
python -m pytest server/tests
```

---

## 4. Cryptographic & Security Rules

1. **Zero Plaintext Rule**: Never transmit or store unencrypted message bodies on the server relay.
2. **Platform Privacy Flags**:
   - Android: `FLAG_SECURE` must remain active in `MainActivity.kt`.
   - Android: `allowBackup="false"` must remain in `AndroidManifest.xml`.
   - iOS: Documents directory must remain marked `isExcludedFromBackup = true`.
   - iOS: `UIBlurEffect` must activate when entering the background.
3. **No Weak Cryptography**: Do not introduce MD5, SHA-1, DES, 3DES, or RSA keys below 2048 bits.
4. **CSPRNG**: All nonces and symmetric keys must be generated using cryptographically secure random number generators (`Random.secure()` or `os.urandom()`).

---

## 5. Submitting Changes

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-enhancement`.
3. Verify that all 4 test suites pass cleanly.
4. Commit your changes with descriptive messages: `git commit -m "Add feature XYZ"`.
5. Open a Pull Request on GitHub.
