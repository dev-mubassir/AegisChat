import 'dart:convert';
import 'dart:typed_data';

import 'package:app/crypto/asymmetric.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('RSA-2048 OAEP-SHA256 and Ed25519 signatures', () {
    test('RSA-2048 key generation runs in background and wraps/unwraps 32-byte key', () async {
      final rsa = RsaOaep();
      final keyPair = await rsa.generateKeyPair(); // runs in isolate

      expect(keyPair.publicKey.modulus!.bitLength, equals(2048));

      // 32-byte AES key
      final aesKey = Uint8List.fromList(List<int>.generate(32, (i) => i * 3 + 1));

      final wrappedKey = rsa.wrapKey(
        publicKey: keyPair.publicKey,
        aesKey: aesKey,
      );

      expect(wrappedKey.length, equals(256)); // 2048 bits = 256 bytes

      final unwrappedKey = rsa.unwrapKey(
        privateKey: keyPair.privateKey,
        wrappedKey: wrappedKey,
      );

      expect(unwrappedKey, equals(aesKey));
    });

    test('two wraps of one key differ (probabilistic OAEP padding)', () async {
      final rsa = RsaOaep();
      final keyPair = await rsa.generateKeyPair();
      final aesKey = Uint8List.fromList(List<int>.generate(32, (i) => (i + 5) % 256));

      final wrap1 = rsa.wrapKey(publicKey: keyPair.publicKey, aesKey: aesKey);
      final wrap2 = rsa.wrapKey(publicKey: keyPair.publicKey, aesKey: aesKey);

      expect(wrap1, isNot(equals(wrap2)));

      // Both still unwrap to the identical key
      expect(rsa.unwrapKey(privateKey: keyPair.privateKey, wrappedKey: wrap1), equals(aesKey));
      expect(rsa.unwrapKey(privateKey: keyPair.privateKey, wrappedKey: wrap2), equals(aesKey));
    });

    test('wrong RSA private key fails to unwrap', () async {
      final rsa = RsaOaep();
      final keyPair1 = await rsa.generateKeyPair();
      final keyPair2 = await rsa.generateKeyPair();
      final aesKey = Uint8List.fromList(List<int>.generate(32, (i) => i));

      final wrappedKey = rsa.wrapKey(publicKey: keyPair1.publicKey, aesKey: aesKey);

      expect(
        () => rsa.unwrapKey(privateKey: keyPair2.privateKey, wrappedKey: wrappedKey),
        throwsArgumentError,
      );
    });

    test('Ed25519 sign and verify round trip', () async {
      final signer = MessageSigner();
      final keyPair = await signer.generateKeyPair();
      final pubBytes = await signer.getPublicKeyBytes(keyPair);
      final message = utf8.encode('SecureChat cryptographic message signing');

      final signature = await signer.sign(keyPair: keyPair, message: message);
      expect(signature.length, equals(64)); // Ed25519 signatures are 64 bytes

      final isValid = await signer.verify(
        publicKeyBytes: pubBytes,
        message: message,
        signatureBytes: signature,
      );
      expect(isValid, isTrue);
    });

    test('tampered Ed25519 signature fails verification', () async {
      final signer = MessageSigner();
      final keyPair = await signer.generateKeyPair();
      final pubBytes = await signer.getPublicKeyBytes(keyPair);
      final message = utf8.encode('Authentic payload');

      final signature = await signer.sign(keyPair: keyPair, message: message);

      // Tamper signature by flipping a byte
      final tamperedSig = Uint8List.fromList(signature);
      tamperedSig[0] ^= 0xFF;

      final isValid = await signer.verify(
        publicKeyBytes: pubBytes,
        message: message,
        signatureBytes: tamperedSig,
      );
      expect(isValid, isFalse);
    });

    test('tampered message fails Ed25519 verification', () async {
      final signer = MessageSigner();
      final keyPair = await signer.generateKeyPair();
      final pubBytes = await signer.getPublicKeyBytes(keyPair);
      final originalMessage = utf8.encode('Original message');
      final tamperedMessage = utf8.encode('Tampered message');

      final signature = await signer.sign(keyPair: keyPair, message: originalMessage);

      final isValid = await signer.verify(
        publicKeyBytes: pubBytes,
        message: tamperedMessage,
        signatureBytes: signature,
      );
      expect(isValid, isFalse);
    });

    test('wrong Ed25519 public key fails verification', () async {
      final signer = MessageSigner();
      final keyPair1 = await signer.generateKeyPair();
      final keyPair2 = await signer.generateKeyPair();
      final pubBytes2 = await signer.getPublicKeyBytes(keyPair2);

      final message = utf8.encode('Secret message');
      final signature = await signer.sign(keyPair: keyPair1, message: message);

      final isValid = await signer.verify(
        publicKeyBytes: pubBytes2,
        message: message,
        signatureBytes: signature,
      );
      expect(isValid, isFalse);
    });
  });
}
