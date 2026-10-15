import 'package:app/auth/app_lock.dart';
import 'package:app/crypto/keystore.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('AppLockManager', () {
    late InMemoryKeyStore keyStore;
    late FakeBiometricService fakeBiometrics;
    late DateTime currentTime;

    DateTime fakeClock() => currentTime;

    setUp(() {
      keyStore = InMemoryKeyStore();
      fakeBiometrics = FakeBiometricService();
      currentTime = DateTime.fromMillisecondsSinceEpoch(1770000000 * 1000);
    });

    test('setupPin requires exactly 6 digits', () async {
      final manager = AppLockManager(
        keyStore: keyStore,
        biometricService: fakeBiometrics,
        clock: fakeClock,
      );

      expect(() => manager.setupPin('12345'), throwsArgumentError);
      expect(() => manager.setupPin('1234567'), throwsArgumentError);
      expect(() => manager.setupPin('abcdef'), throwsArgumentError);

      await manager.setupPin('123456');
      expect(await manager.hasPinSetup(), isTrue);
      expect(manager.isLocked, isFalse);
    });

    test('verifyPin unlocks on correct PIN and rejects wrong PIN', () async {
      final manager = AppLockManager(
        keyStore: keyStore,
        biometricService: fakeBiometrics,
        clock: fakeClock,
      );

      await manager.setupPin('654321');
      manager.lock();
      expect(manager.isLocked, isTrue);

      // Wrong PIN
      final wrongRes = await manager.verifyPin('000000');
      expect(wrongRes, isFalse);
      expect(manager.isLocked, isTrue);

      // Correct PIN
      final rightRes = await manager.verifyPin('654321');
      expect(rightRes, isTrue);
      expect(manager.isLocked, isFalse);
    });

    test('growing delays enforced after repeated failed attempts', () async {
      final manager = AppLockManager(
        keyStore: keyStore,
        biometricService: fakeBiometrics,
        clock: fakeClock,
      );

      await manager.setupPin('112233');
      manager.lock();

      // Attempts 1, 2, 3: no lockout delay
      expect(await manager.verifyPin('000000'), isFalse);
      expect(await manager.verifyPin('000000'), isFalse);
      expect(await manager.verifyPin('000000'), isFalse);

      // 4th attempt: triggers 5s lockout
      expect(await manager.verifyPin('000000'), isFalse);

      // Immediate 5th attempt throws AppLockoutException
      await expectLater(
        manager.verifyPin('000000'),
        throwsA(isA<AppLockoutException>().having((e) => e.remainingSeconds, 'remainingSeconds', 5)),
      );

      // Advance clock 6 seconds -> allowed again
      currentTime = currentTime.add(const Duration(seconds: 6));

      // 5th attempt: triggers 15s lockout
      expect(await manager.verifyPin('000000'), isFalse);

      await expectLater(
        manager.verifyPin('000000'),
        throwsA(isA<AppLockoutException>().having((e) => e.remainingSeconds, 'remainingSeconds', 15)),
      );
    });

    test('wipes local keys after 10 failures', () async {
      final manager = AppLockManager(
        keyStore: keyStore,
        biometricService: fakeBiometrics,
        clock: fakeClock,
      );

      await manager.setupPin('998877');
      await keyStore.write('secret_user_message', 'sensitive_plaintext_chat');
      manager.lock();

      // Run 9 failed attempts advancing clock each time through the lockouts
      for (var i = 1; i <= 9; i++) {
        await manager.verifyPin('000000');
        // Advance clock past the lockout delay for next attempt
        currentTime = currentTime.add(const Duration(seconds: 400));
      }

      // 10th failure: must wipe everything!
      await expectLater(
        manager.verifyPin('000000'),
        throwsA(isA<AppWipedException>()),
      );

      expect(manager.isWiped, isTrue);
      expect(manager.isLocked, isTrue);
      expect(await keyStore.read('secret_user_message'), isNull);
      expect(await manager.hasPinSetup(), isFalse);
    });

    test('auto-locks after 60 seconds in the background', () async {
      final manager = AppLockManager(
        keyStore: keyStore,
        biometricService: fakeBiometrics,
        clock: fakeClock,
      );

      await manager.setupPin('123456');
      expect(manager.isLocked, isFalse);

      // App backgrounded for 30s -> does not lock
      manager.onAppPaused();
      currentTime = currentTime.add(const Duration(seconds: 30));
      manager.onAppResumed();
      expect(manager.isLocked, isFalse);

      // App backgrounded for 61s -> auto-locks!
      manager.onAppPaused();
      currentTime = currentTime.add(const Duration(seconds: 61));
      manager.onAppResumed();
      expect(manager.isLocked, isTrue);
    });

    test('biometric authentication unlocks app on success', () async {
      final manager = AppLockManager(
        keyStore: keyStore,
        biometricService: fakeBiometrics,
        clock: fakeClock,
      );

      await manager.setupPin('123456');
      manager.lock();
      expect(manager.isLocked, isTrue);

      fakeBiometrics.shouldSucceed = false;
      final failedBio = await manager.authenticateBiometric();
      expect(failedBio, isFalse);
      expect(manager.isLocked, isTrue);

      fakeBiometrics.shouldSucceed = true;
      final okBio = await manager.authenticateBiometric();
      expect(okBio, isTrue);
      expect(manager.isLocked, isFalse);
    });
  });
}
