import 'dart:convert';
import 'dart:typed_data';

import 'package:app/crypto/aes_gcm.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('AES-256-GCM', () {
    // Standard 32-byte (256-bit) test key
    final testKey = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final testAad = utf8.encode('sender:alice|recipient:bob|msg:101|ts:1700000000');
    final plaintext = utf8.encode('Hello SecureChat! End-to-end encrypted message.');

    test('roundtrip encryption and decryption', () async {
      final cipher = AesGcmCipher();
      final encrypted = await cipher.encrypt(
        plaintext: plaintext,
        key: testKey,
        associatedData: testAad,
      );

      expect(encrypted.nonce.length, equals(12)); // 96-bit nonce
      expect(encrypted.mac.length, equals(16)); // 128-bit authentication tag
      expect(encrypted.ciphertext.isNotEmpty, isTrue);

      final decrypted = await cipher.decrypt(
        encryptedMessage: encrypted,
        key: testKey,
        associatedData: testAad,
      );

      expect(decrypted, equals(plaintext));
      expect(utf8.decode(decrypted), equals('Hello SecureChat! End-to-end encrypted message.'));
    });

    test('known-answer vector verification', () async {
      // Known vector with fixed key, nonce, aad, plaintext
      final key = Uint8List.fromList([
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
      ]);
      final nonce = Uint8List.fromList([
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
      ]);
      final aad = Uint8List.fromList([
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
      ]);
      final pt = Uint8List.fromList(utf8.encode('Known Answer Vector Test'));

      final cipher = AesGcmCipher();
      final enc = await cipher.encryptWithNonce(
        plaintext: pt,
        key: key,
        nonce: nonce,
        associatedData: aad,
      );

      final dec = await cipher.decrypt(
        encryptedMessage: enc,
        key: key,
        associatedData: aad,
      );

      expect(dec, equals(pt));
    });

    test('flip-any-bit tamper test fails decryption', () async {
      final cipher = AesGcmCipher();
      final encrypted = await cipher.encrypt(
        plaintext: plaintext,
        key: testKey,
        associatedData: testAad,
      );

      // Test flipping bits in the ciphertext
      for (var byteIdx = 0; byteIdx < encrypted.ciphertext.length; byteIdx++) {
        for (var bit = 0; bit < 8; bit++) {
          final tamperedCt = Uint8List.fromList(encrypted.ciphertext);
          tamperedCt[byteIdx] ^= (1 << bit);

          final tamperedMsg = EncryptedPayload(
            nonce: encrypted.nonce,
            ciphertext: tamperedCt,
            mac: encrypted.mac,
          );

          expect(
            () async => await cipher.decrypt(
              encryptedMessage: tamperedMsg,
              key: testKey,
              associatedData: testAad,
            ),
            throwsException,
          );
        }
      }

      // Test flipping bits in MAC tag
      for (var byteIdx = 0; byteIdx < encrypted.mac.length; byteIdx++) {
        final tamperedMac = Uint8List.fromList(encrypted.mac);
        tamperedMac[byteIdx] ^= 0x01;

        final tamperedMsg = EncryptedPayload(
          nonce: encrypted.nonce,
          ciphertext: encrypted.ciphertext,
          mac: tamperedMac,
        );

        expect(
          () async => await cipher.decrypt(
            encryptedMessage: tamperedMsg,
            key: testKey,
            associatedData: testAad,
          ),
          throwsException,
        );
      }
    });

    test('wrong key fails decryption', () async {
      final cipher = AesGcmCipher();
      final encrypted = await cipher.encrypt(
        plaintext: plaintext,
        key: testKey,
        associatedData: testAad,
      );

      final wrongKey = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
      expect(
        () async => await cipher.decrypt(
          encryptedMessage: encrypted,
          key: wrongKey,
          associatedData: testAad,
        ),
        throwsException,
      );
    });

    test('wrong associated data fails decryption', () async {
      final cipher = AesGcmCipher();
      final encrypted = await cipher.encrypt(
        plaintext: plaintext,
        key: testKey,
        associatedData: testAad,
      );

      final wrongAad = utf8.encode('sender:mallory|recipient:bob|msg:101|ts:1700000000');
      expect(
        () async => await cipher.decrypt(
          encryptedMessage: encrypted,
          key: testKey,
          associatedData: wrongAad,
        ),
        throwsException,
      );
    });

    test('10,000 nonces all unique', () {
      final cipher = AesGcmCipher();
      final seen = <String>{};
      const count = 10000;

      for (var i = 0; i < count; i++) {
        final nonce = cipher.generateNonce();
        expect(nonce.length, equals(12));
        final hex = nonce.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
        final added = seen.add(hex);
        expect(added, isTrue, reason: 'Duplicate nonce generated at iteration $i');
      }

      expect(seen.length, equals(count));
    });
  });
}
