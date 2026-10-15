# iOS Sideloading & Deployment Guide

This document explains how to build, sideload, and deploy SecureChat on Apple iOS devices, comparing a free Apple Developer Account (personal Apple ID) versus a paid Apple Developer Program account ($99/year).

---

## 1. Account Comparison Matrix

| Feature / Capability | Free Apple ID (Personal Team) | Paid Apple Developer Program ($99/yr) |
| :--- | :--- | :--- |
| **Provisioning Expiry** | **7 Days** (requires weekly re-signing) | **1 Year** (365 days per ad-hoc profile) |
| **Maximum Installed Sideloaded Apps** | **3 active apps** per device | **Unlimited** within device limits |
| **Apple Push Notification service (APNs)** | ❌ **Not Supported** (entitlement denied) | ✅ **Supported** (background push wakes app) |
| **Associated Domains & Passkeys** | ❌ **Not Supported** | ✅ **Supported** |
| **Secure Enclave Access (P-256 / Keychain)**| ✅ **Supported** (local Keychain works) | ✅ **Supported** |
| **Background WebSockets / Sockets** | ⚠️ Suspended when app is backgrounded | ⚠️ Suspended (APNs wake needed for alerts) |
| **Distribution Methods** | Sideload via AltStore / Sideloadly / Xcode | TestFlight, Ad-Hoc, or App Store |

---

## 2. Sideloading with a Free Apple ID

With a standard free Apple ID, you can sideload SecureChat to your personal iPhone or iPad without paying Apple's $99 annual fee.

### Option A: Using AltStore or SideStore
1. **Download AltServer**: Install [AltServer](https://altstore.io/) on your macOS or Windows machine.
2. **Connect Device**: Connect your iPhone to your computer via USB and trust the computer.
3. **Install AltStore**: Click AltServer in the system tray/menu bar -> *Install AltStore* -> select your device. Enter your Apple ID and password.
4. **Enable Developer Mode (iOS 16+)**: On iPhone, go to **Settings** > **Privacy & Security** > **Developer Mode**, toggle it **ON**, and reboot.
5. **Install SecureChat**:
   - Open AltStore on your device.
   - Tap `+` and select `SecureChat.ipa` (or use AltServer to sideload the IPA directly).
   - AltStore signs the app using your personal certificate.
6. **Weekly Refresh**: Because free provisioning profiles expire after 7 days, AltStore automatically refreshes the certificate over local Wi-Fi when running in the background.

### Option B: Using Sideloadly
1. Download [Sideloadly](https://sideloadly.io/) (Windows/macOS).
2. Connect iPhone via USB.
3. Drag and drop `SecureChat.ipa` into Sideloadly.
4. Enter your Apple ID email.
5. Click **Start** to sign and install the app.
6. On iPhone: Go to **Settings** > **General** > **VPN & Device Management** > tap your Apple ID > tap **Trust**.

---

## 3. Paid Apple Developer Account Deployment

With a paid Apple Developer Program membership:
1. **TestFlight**: Distribute builds to up to 10,000 external testers or 100 internal testers without physical cable connection. Builds remain valid for 90 days.
2. **Push Notifications**: Full APNs certificate configuration enables remote wake-up notifications for incoming encrypted chats.
3. **Ad-Hoc Distribution**: Register up to 100 UDIDs per device family for 1-year signed provisioning profiles.

---

## 4. Privacy & Platform Enforcements on iOS

SecureChat implements native iOS privacy protections in `AppDelegate.swift`:
1. **App Switcher Privacy Blur**: When the application resigns active state (`applicationWillResignActive`), a full-screen `UIBlurEffect` view is overlaid onto the primary window. This prevents sensitive chat content from appearing in screenshots taken by the iOS multitasking switcher.
2. **iCloud Backup Exclusion**: Local message databases and key stores explicitly set `isExcludedFromBackup = true` on `URLResourceValues` to ensure data never syncs to unencrypted iCloud or iTunes backups.
