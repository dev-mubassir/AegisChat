import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:app/crypto/keystore.dart';
import 'package:local_auth/local_auth.dart';
import 'package:pointycastle/export.dart';

class AppLockoutException implements Exception {
  final int remainingSeconds;
  AppLockoutException(this.remainingSeconds);
  @override
  String toString() => 'AppLockoutException: Locked out for $remainingSeconds more seconds';
}

class AppWipedException implements Exception {
  final String message;
  AppWipedException(this.message);
  @override
  String toString() => 'AppWipedException: $message';
}

/// Abstract interface for platform biometric authentication.
abstract class BiometricService {
  Future<bool> canAuthenticate();
  Future<bool> authenticate({required String reason});
}

/// Production implementation using local_auth.
class LocalAuthBiometricService implements BiometricService {
  final LocalAuthentication _auth = LocalAuthentication();

  @override
  Future<bool> canAuthenticate() async {
    final canCheck = await _auth.canCheckBiometrics;
    final isDeviceSupported = await _auth.isDeviceSupported();
    return canCheck && isDeviceSupported;
  }

  @override
  Future<bool> authenticate({required String reason}) async {
    try {
      return await _auth.authenticate(
        localizedReason: reason,
      );
    } catch (_) {
      return false;
    }
  }
}

/// In-memory fake biometric service for tests.
class FakeBiometricService implements BiometricService {
  bool shouldSucceed;
  bool isAvailable;

  FakeBiometricService({this.shouldSucceed = true, this.isAvailable = true});

  @override
  Future<bool> canAuthenticate() async => isAvailable;

  @override
  Future<bool> authenticate({required String reason}) async {
    if (!isAvailable) return false;
    return shouldSucceed;
  }
}

/// Coordinates PIN security (Argon2id), biometrics, rate-limiting delays, 10-failure wiping,
/// and 60-second background auto-locking.
class AppLockManager {
  final KeyStore _keyStore;
  final BiometricService _biometricService;
  final DateTime Function() _clock;

  static const String keyPinSalt = 'applock_pin_salt';
  static const String keyPinHash = 'applock_pin_hash';
  static const String keyFailedAttempts = 'applock_failed_attempts';
  static const String keyLockoutUntil = 'applock_lockout_until';

  static const int autoLockBackgroundSeconds = 60;
  static const int maxAllowedFailures = 10;

  bool _isLocked = true;
  bool _isWiped = false;
  DateTime? _pausedAt;

  bool get isLocked => _isLocked;
  bool get isWiped => _isWiped;

  AppLockManager({
    required this._keyStore,
    BiometricService? biometricService,
    DateTime Function()? clock,
  })  : _biometricService = biometricService ?? LocalAuthBiometricService(),
        _clock = clock ?? DateTime.now;

  /// Sets lock state explicitly (e.g. on cold start or manual lock).
  void lock() {
    _isLocked = true;
  }

  /// Called when the application moves to the background (paused).
  void onAppPaused() {
    _pausedAt = _clock();
  }

  /// Called when the application returns to the foreground (resumed).
  /// Enforces the 60-second auto-lock rule.
  void onAppResumed() {
    if (_pausedAt != null) {
      final elapsed = _clock().difference(_pausedAt!).inSeconds;
      if (elapsed >= autoLockBackgroundSeconds) {
        _isLocked = true;
      }
      _pausedAt = null;
    }
  }

  /// Derives Argon2id hash from a PIN and salt.
  static Uint8List deriveArgon2idKey(String pin, Uint8List salt) {
    final generator = Argon2BytesGenerator();
    final params = Argon2Parameters(
      Argon2Parameters.ARGON2_id,
      salt,
      version: Argon2Parameters.ARGON2_VERSION_13,
      iterations: 2,
      memoryPowerOf2: 12, // 4 MB memory
      lanes: 1,
      desiredKeyLength: 32,
    );
    generator.init(params);
    return generator.process(Uint8List.fromList(utf8.encode(pin)));
  }

  /// Calculates progressive delay in seconds after consecutive failed attempts.
  static int getDelayForFailures(int failures) {
    if (failures <= 3) return 0;
    switch (failures) {
      case 4:
        return 5;
      case 5:
        return 15;
      case 6:
        return 30;
      case 7:
        return 60;
      case 8:
        return 120;
      case 9:
        return 300;
      default:
        return 300;
    }
  }

  /// Configures a new 6-digit PIN using Argon2id key derivation.
  Future<void> setupPin(String pin) async {
    if (!RegExp(r'^\d{6}$').hasMatch(pin)) {
      throw ArgumentError('PIN must be exactly 6 digits');
    }

    final rand = Random.secure();
    final salt = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      salt[i] = rand.nextInt(256);
    }

    final hash = deriveArgon2idKey(pin, salt);

    await _keyStore.write(keyPinSalt, base64.encode(salt));
    await _keyStore.write(keyPinHash, base64.encode(hash));
    await _keyStore.delete(keyFailedAttempts);
    await _keyStore.delete(keyLockoutUntil);

    _isLocked = false;
    _isWiped = false;
  }

  /// Checks if a PIN has been set up.
  Future<bool> hasPinSetup() async {
    final hash = await _keyStore.read(keyPinHash);
    return hash != null && hash.isNotEmpty;
  }

  /// Verifies entered PIN with progressive rate-limit delays and 10-try wipe protection.
  Future<bool> verifyPin(String pin) async {
    final now = _clock();

    // 1. Check if user is currently locked out by a growing delay
    final lockoutStr = await _keyStore.read(keyLockoutUntil);
    if (lockoutStr != null) {
      final lockoutUntilEpoch = int.tryParse(lockoutStr) ?? 0;
      final nowEpoch = now.millisecondsSinceEpoch ~/ 1000;
      if (nowEpoch < lockoutUntilEpoch) {
        throw AppLockoutException(lockoutUntilEpoch - nowEpoch);
      }
    }

    final saltStr = await _keyStore.read(keyPinSalt);
    final hashStr = await _keyStore.read(keyPinHash);
    if (saltStr == null || hashStr == null) {
      throw StateError('No PIN has been configured');
    }

    final salt = base64.decode(saltStr);
    final expectedHash = base64.decode(hashStr);

    final actualHash = deriveArgon2idKey(pin, salt);

    // Constant-time comparison
    var diff = 0;
    if (actualHash.length != expectedHash.length) {
      diff = 1;
    } else {
      for (var i = 0; i < actualHash.length; i++) {
        diff |= actualHash[i] ^ expectedHash[i];
      }
    }

    if (diff == 0) {
      // Correct PIN: reset failed attempts counter & lockout, unlock app
      await _keyStore.delete(keyFailedAttempts);
      await _keyStore.delete(keyLockoutUntil);
      _isLocked = false;
      return true;
    } else {
      // Incorrect PIN: increment failure counter
      final attemptsStr = await _keyStore.read(keyFailedAttempts);
      final currentAttempts = (int.tryParse(attemptsStr ?? '0') ?? 0) + 1;
      await _keyStore.write(keyFailedAttempts, currentAttempts.toString());

      if (currentAttempts >= maxAllowedFailures) {
        // SECURITY REQUIREMENT: Wipe all local keys after 10 failures
        await _keyStore.deleteAll();
        _isLocked = true;
        _isWiped = true;
        throw AppWipedException(
          'Maximum failed attempts ($maxAllowedFailures) exceeded. All local keys have been wiped.',
        );
      }

      // Calculate growing delay
      final delaySeconds = getDelayForFailures(currentAttempts);
      if (delaySeconds > 0) {
        final lockoutUntil = (now.millisecondsSinceEpoch ~/ 1000) + delaySeconds;
        await _keyStore.write(keyLockoutUntil, lockoutUntil.toString());
      }

      return false;
    }
  }

  /// Attempts to unlock the app using biometric authentication.
  Future<bool> authenticateBiometric({String reason = 'Unlock SecureChat'}) async {
    final canAuth = await _biometricService.canAuthenticate();
    if (!canAuth) return false;

    final success = await _biometricService.authenticate(reason: reason);
    if (success) {
      await _keyStore.delete(keyFailedAttempts);
      await _keyStore.delete(keyLockoutUntil);
      _isLocked = false;
      return true;
    }
    return false;
  }
}
