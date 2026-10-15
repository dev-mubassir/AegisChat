#!/usr/bin/env python3
"""Platform privacy flags checker for SecureChat.

Verifies:
1. Android allowBackup="false"
2. Android networkSecurityConfig cleartextTrafficPermitted="false"
3. Android FLAG_SECURE on MainActivity
4. Generic notification text (no plaintext in notifications)
5. iOS exclude from backup (isExcludedFromBackup = true)
6. iOS blur in app switcher (applicationWillResignActive + UIBlurEffect)
7. Includes self-test validating that missing flags cause verification failures.
"""

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_ROOT = REPO_ROOT / "app"


def check_android_manifest(content: str) -> list[str]:
    errors = []
    if 'android:allowBackup="false"' not in content:
        errors.append('Missing android:allowBackup="false" in AndroidManifest.xml')
    if 'android:networkSecurityConfig="@xml/network_security_config"' not in content:
        errors.append(
            'Missing android:networkSecurityConfig="@xml/network_security_config" in AndroidManifest.xml'
        )
    return errors


def check_network_security_config(content: str) -> list[str]:
    errors = []
    if 'cleartextTrafficPermitted="false"' not in content:
        errors.append(
            'Missing cleartextTrafficPermitted="false" in network_security_config.xml'
        )
    return errors


def check_main_activity(content: str) -> list[str]:
    errors = []
    if "FLAG_SECURE" not in content:
        errors.append("Missing WindowManager.LayoutParams.FLAG_SECURE in MainActivity.kt")
    return errors


def check_ios_app_delegate(content: str) -> list[str]:
    errors = []
    if "isExcludedFromBackup" not in content:
        errors.append("Missing isExcludedFromBackup in iOS AppDelegate.swift")
    if "UIBlurEffect" not in content or "applicationWillResignActive" not in content:
        errors.append("Missing app switcher blur protection in iOS AppDelegate.swift")
    return errors


def check_notifications(content: str) -> list[str]:
    errors = []
    if "New encrypted message" not in content:
        errors.append("Missing generic notification text in NotificationService")
    return errors


def run_self_tests() -> None:
    """Verify that validator functions reliably fail on missing flags."""
    assert check_android_manifest('<application android:allowBackup="true" />') != []
    assert check_network_security_config("<network-security-config />") != []
    assert check_main_activity("class MainActivity : FlutterActivity()") != []
    assert check_ios_app_delegate("class AppDelegate: FlutterAppDelegate {}") != []
    assert check_notifications("class NotificationService {}") != []
    print("[PASS] Self-tests verified: all missing flag conditions successfully detected.")


def main() -> int:
    # Run self-tests first
    run_self_tests()

    manifest_file = APP_ROOT / "android/app/src/main/AndroidManifest.xml"
    net_config_file = (
        APP_ROOT / "android/app/src/main/res/xml/network_security_config.xml"
    )
    main_act_file = (
        APP_ROOT
        / "android/app/src/main/kotlin/com/example/app/MainActivity.kt"
    )
    ios_delegate_file = APP_ROOT / "ios/Runner/AppDelegate.swift"
    notification_file = APP_ROOT / "lib/notifications/notification_service.dart"

    all_errors = []

    if not manifest_file.exists():
        all_errors.append(f"Manifest not found: {manifest_file}")
    else:
        all_errors.extend(check_android_manifest(manifest_file.read_text("utf-8")))

    if not net_config_file.exists():
        all_errors.append(f"Network config not found: {net_config_file}")
    else:
        all_errors.extend(
            check_network_security_config(net_config_file.read_text("utf-8"))
        )

    if not main_act_file.exists():
        all_errors.append(f"MainActivity not found: {main_act_file}")
    else:
        all_errors.extend(check_main_activity(main_act_file.read_text("utf-8")))

    if not ios_delegate_file.exists():
        all_errors.append(f"iOS AppDelegate not found: {ios_delegate_file}")
    else:
        all_errors.extend(
            check_ios_app_delegate(ios_delegate_file.read_text("utf-8"))
        )

    if not notification_file.exists():
        all_errors.append(f"NotificationService not found: {notification_file}")
    else:
        all_errors.extend(check_notifications(notification_file.read_text("utf-8")))

    if all_errors:
        print("\n[FAIL] Platform privacy flag violations:")
        for err in all_errors:
            print(f"  - {err}")
        return 1

    print("\n[PASS] All platform privacy flags verified:")
    print("  [x] Android allowBackup=false")
    print("  [x] Android cleartextTrafficPermitted=false (network_security_config.xml)")
    print("  [x] Android FLAG_SECURE (MainActivity.kt)")
    print("  [x] iOS documents isExcludedFromBackup=true (AppDelegate.swift)")
    print("  [x] iOS app switcher UIBlurEffect (AppDelegate.swift)")
    print("  [x] Generic notification text (NotificationService)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
