# SecureChat Manual Verification Checklist (Real Device)

This document provides a step-by-step physical device verification checklist for validating hardware security features, OS-level privacy flags, and end-to-end cryptographic integrity.

---

## 1. Android Physical Device Verification

### A. Screenshot & Screen Recording Prevention (`FLAG_SECURE`)
1. Open SecureChat on a physical Android device.
2. Attempt to capture a screenshot using physical hardware buttons (Power + Volume Down).
   - **Expected Result**: Android rejects the capture with a toast message: *"Can't take screenshot due to security policy"* or saves a completely black image.
3. Open recent apps / multitasking switcher.
   - **Expected Result**: The app thumbnail preview is blank/black, preventing sensitive message exposure.
4. Start a screen recording tool (built-in or third-party) and navigate within the app.
   - **Expected Result**: Recorded video shows a black screen for all SecureChat views.

### B. Backup Extraction Defense (`allowBackup="false"`)
1. Connect the phone to a computer with USB debugging enabled.
2. Run ADB backup:
   ```bash
   adb backup -f securechat.ab -noapk com.example.app
   ```
3. **Expected Result**: ADB reports backup rejected or produces an empty archive (0 bytes payload). Application data cannot be extracted via ADB or cloud restore.

### C. Cleartext Traffic Blocking (`network_security_config.xml`)
1. In settings, configure an insecure HTTP relay address (e.g., `http://192.168.1.100:8000`).
2. Attempt to connect or register.
   - **Expected Result**: Android network stack throws `IOException: Cleartext HTTP traffic to 192.168.1.100 not permitted`. All plaintext HTTP/WS connections are blocked at the OS layer.

### D. Hardware Keystore / StrongBox (`HardwareDeviceKey`)
1. Launch app and initiate registration.
2. Verify Android Keystore key generation succeeds with `KeyProperties.PURPOSE_SIGN` and `KeyGenParameterSpec` backed by hardware (StrongBox Keymaster if available).
3. Confirm private key is non-exportable and never leaves the secure element.

### E. App Lock, Progressive Lockout & 10-Failure Wipe
1. Set up a 6-digit PIN on initial onboarding.
2. Enter incorrect PIN 3 times: App shows incorrect attempt count with no delay.
3. Enter incorrect PIN a 4th time: App enforces 5-second countdown lock.
4. Repeat with consecutive wrong PINs: Cooldown increases to 15s, 30s, 60s, 120s, 300s.
5. Enter incorrect PIN the 10th time:
   - **Expected Result**: App triggers complete emergency cryptographic wipe (`deleteAll`). Local message store, keys, and session tokens are permanently wiped. App resets to registration screen.

### F. 60-Second Auto-Lock
1. Unlock app and open a chat.
2. Press Home button or switch to another app for 65 seconds.
3. Return to SecureChat.
   - **Expected Result**: App immediately presents the Lock Screen requiring PIN or biometric verification before showing any chat content.

---

## 2. iOS Physical Device Verification

### A. App Switcher Privacy Blur
1. Open SecureChat on an iPhone.
2. Swipe up from the bottom to enter the iOS App Switcher.
3. **Expected Result**: `AppDelegate` overlays a `UIBlurEffect` view over the primary window. No chat bubbles, contacts, or names are legible in the switcher snapshot.

### B. iCloud Backup Exclusion
1. Inspect app data storage path in application sandbox.
2. **Expected Result**: Database and keystore files have `NSURLIsExcludedFromBackupKey = true`. Backing up to iCloud or iTunes does not export sensitive files.

### C. Secure Enclave Isolation
1. Verify device key pair is created in Secure Enclave using `kSecAttrTokenIDSecureEnclave` and `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
2. Confirm biometric evaluation (`kSecAccessControlBiometryAny`) gates signature generation.

---

## 3. End-to-End Cryptographic & Relay Checks

### A. Contact Card & Safety Number Verification
1. Device A displays Contact QR code (`user_id` + public signing/encapsulation keys).
2. Device B scans Device A's QR code to add contact.
3. Open Safety Number screen on both devices:
   - Compare the 60-digit formatted numeric string (12 blocks of 5 digits).
   - **Expected Result**: The 60-digit number is bit-for-bit identical on both devices.
4. Tap **Mark as Verified**.

### B. MITM Key Change Detection Alert
1. Simulate a key compromise or device reinstallation with a new identity key for Contact A.
2. Contact A attempts to send a message to Device B.
3. **Expected Result**: Device B displays a prominent warning banner: *"Contact Key Changed! Verification Required"*. The message is not decrypted until the user explicitly re-verifies the safety number.

### C. Relay Zero-Knowledge & Delivery Deletion
1. Device A sends an encrypted message to Device B.
2. Verify message displays "Sending" -> "Sent" (reached relay).
3. Query server database `sqlite3 server.db "SELECT * FROM messages;"`:
   - Verify payload is opaque Base64 ciphertext with zero plaintext markers.
4. Bring Device B online. Device B fetches and acknowledges message.
5. Query server database again:
   - **Expected Result**: Message row is deleted immediately upon receipt of `ack`.

### D. Generic Notifications
1. Lock Device B and send a message from Device A.
2. Observe push / local notification on Device B's lock screen.
   - **Expected Result**: Notification text displays generic alert: *"New Secure Message"*. Neither sender identity nor message text is disclosed.
