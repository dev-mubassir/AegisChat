import 'dart:convert';
import 'dart:typed_data';

import 'package:app/crypto/keystore.dart';
import 'package:app/crypto/safety_number.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('KeyStore', () {
    test('in-memory keystore read, write, contains, delete, deleteAll', () async {
      final store = InMemoryKeyStore();

      expect(await store.containsKey('secret_key'), isFalse);
      expect(await store.read('secret_key'), isNull);

      await store.write('secret_key', 'super_secret_value_123');
      expect(await store.containsKey('secret_key'), isTrue);
      expect(await store.read('secret_key'), equals('super_secret_value_123'));

      await store.write('another_key', 'value_456');
      expect(await store.read('another_key'), equals('value_456'));

      await store.delete('secret_key');
      expect(await store.containsKey('secret_key'), isFalse);
      expect(await store.read('secret_key'), isNull);
      expect(await store.read('another_key'), equals('value_456'));

      await store.deleteAll();
      expect(await store.containsKey('another_key'), isFalse);
      expect(await store.read('another_key'), isNull);
    });
  });

  group('Safety Numbers and QR payload', () {
    final keyA = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final keyB = Uint8List.fromList(List<int>.generate(32, (i) => 255 - i));
    final keyC = Uint8List.fromList(List<int>.generate(32, (i) => (i * 7) % 256));

    test('safety number is exactly 60 digits formatted in 12 groups of 5', () {
      final safetyNum = SafetyNumber.compute(keyA, keyB);
      final rawDigits = safetyNum.replaceAll(' ', '');

      expect(rawDigits.length, equals(60));
      expect(RegExp(r'^\d{60}$').hasMatch(rawDigits), isTrue);

      final groups = safetyNum.split(' ');
      expect(groups.length, equals(12));
      for (final g in groups) {
        expect(g.length, equals(5));
      }
    });

    test('safety number is symmetric: identical on both phones regardless of key order', () {
      final numOnAlicePhone = SafetyNumber.compute(keyA, keyB);
      final numOnBobPhone = SafetyNumber.compute(keyB, keyA);

      expect(numOnAlicePhone, equals(numOnBobPhone));
    });

    test('different keys produce completely different safety numbers', () {
      final numAB = SafetyNumber.compute(keyA, keyB);
      final numAC = SafetyNumber.compute(keyA, keyC);

      expect(numAB, isNot(equals(numAC)));
    });

    test('QR payload generation and verification', () {
      final qrAlice = SafetyNumber.generateQrPayload(keyA, keyB);
      final qrBob = SafetyNumber.generateQrPayload(keyB, keyA);

      // Must be completely identical on both phones
      expect(qrAlice, equals(qrBob));

      final decoded = json.decode(qrAlice);
      expect(decoded['v'], equals(1));
      expect(decoded['fingerprint'], equals(SafetyNumber.compute(keyA, keyB)));

      final verified = SafetyNumber.verifyQrPayload(
        qrPayload: qrAlice,
        localKey: keyA,
        remoteKey: keyB,
      );
      expect(verified, isTrue);

      final wrongKeyVerify = SafetyNumber.verifyQrPayload(
        qrPayload: qrAlice,
        localKey: keyA,
        remoteKey: keyC,
      );
      expect(wrongKeyVerify, isFalse);
    });
  });
}
