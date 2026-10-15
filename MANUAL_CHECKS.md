# SecureChat Manual Verification & Hardware Checks

This document records the security-critical features that cannot be verified automatically in a headless CI environment and must be manually verified on physical hardware (Android / iOS).

---

## 1. Hardware Device Keys (T13)

### Android Keystore / StrongBox
- **Requirement**: The device authentication key must be generated within the Android Keystore (backed by StrongBox / TEE if available).
- **Properties**:
  - Algorithm: ECDSA P-256 (`KeyProperties.KEY_ALGORITHM_EC`, curve `secp256r1`).
  - Purposely non-exportable: `setUserAuthenticationRequired(true)` for biometric gating.
  - Digest: SHA-256.
- **Manual Verification Steps on Real Android Phone**:
  1. Build debug APK: `flutter build apk --debug`.
  2. Sideload onto physical Android test device: `adb install -r build/app/outputs/flutter-apk/app-debug.apk`.
  3. Register new device: Confirm biometric prompt (fingerprint or face unlock) appears when generating key and signing challenge.
  4. Attempt extraction: Verify key cannot be extracted via root or debug bridge.

### iOS Secure Enclave
- **Requirement**: The device authentication key must be generated in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`).
- **Properties**:
  - Algorithm: 256-bit elliptic curve (`kSecAttrKeyTypeECSECPrimeRandom`).
  - Access Control: `kSecAccessControlBiometryAny` or `kSecAccessControlUserPresence`.
  - Non-exportable private key.
- **Manual Verification Steps on Mac & Physical iPhone**:
  1. Open project in Xcode: `open ios/Runner.xcworkspace`.
  2. Build and run on physical iPhone connected via USB.
  3. Trigger login / challenge flow: verify Face ID / Touch ID prompt appears before signing.

---

## 2. App Lock & Biometrics (T14)
- **Manual Verification**:
  1. Background the app for 60 seconds; bring to foreground; verify biometric/PIN unlock screen appears.
  2. Test 10 consecutive incorrect PIN attempts; verify all secure storage keys are wiped.

---

## 3. Platform Privacy Flags (T20)
- **Manual Verification**:
  1. `FLAG_SECURE`: On Android phone, attempt taking a screenshot or recording screen while in chat; verify Android blocks screenshot with "Can't take screenshot due to security policy".
  2. Task switcher: Switch to recent apps; verify preview screen is blurred/blanked.
  3. Backup: Run `adb backup`; verify application data is excluded (`allowBackup=false`).
