import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Represents an AES-256-GCM encrypted payload with a 96-bit nonce and authentication tag.
class EncryptedPayload {
  final Uint8List nonce;
  final Uint8List ciphertext;
  final Uint8List mac;

  EncryptedPayload({
    required this.nonce,
    required this.ciphertext,
    required this.mac,
  });

  /// Serializes to a combined byte buffer: [12 bytes nonce][16 bytes mac][N bytes ciphertext]
  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.add(nonce);
    builder.add(mac);
    builder.add(ciphertext);
    return builder.toBytes();
  }

  /// Deserializes from a combined byte buffer: [12 bytes nonce][16 bytes mac][N bytes ciphertext]
  factory EncryptedPayload.fromBytes(List<int> bytes) {
    if (bytes.length < 28) {
      throw ArgumentError('Payload too short for AES-GCM envelope');
    }
    final nonce = Uint8List.fromList(bytes.sublist(0, 12));
    final mac = Uint8List.fromList(bytes.sublist(12, 28));
    final ciphertext = Uint8List.fromList(bytes.sublist(28));
    return EncryptedPayload(nonce: nonce, ciphertext: ciphertext, mac: mac);
  }
}

/// AES-256-GCM authenticated encryption and decryption.
class AesGcmCipher {
  final AesGcm _algorithm = AesGcm.with256bits();
  final Random _secureRandom = Random.secure();

  /// Generates a fresh random 96-bit (12-byte) nonce using cryptographically secure random.
  Uint8List generateNonce() {
    final nonce = Uint8List(12);
    for (var i = 0; i < 12; i++) {
      nonce[i] = _secureRandom.nextInt(256);
    }
    return nonce;
  }

  /// Encrypts [plaintext] using a fresh random 96-bit nonce, 256-bit [key], and optional [associatedData].
  Future<EncryptedPayload> encrypt({
    required List<int> plaintext,
    required List<int> key,
    List<int>? associatedData,
  }) async {
    final nonce = generateNonce();
    return encryptWithNonce(
      plaintext: plaintext,
      key: key,
      nonce: nonce,
      associatedData: associatedData,
    );
  }

  /// Encrypts [plaintext] with a specified [nonce] (must be 12 bytes / 96 bits).
  Future<EncryptedPayload> encryptWithNonce({
    required List<int> plaintext,
    required List<int> key,
    required List<int> nonce,
    List<int>? associatedData,
  }) async {
    if (key.length != 32) {
      throw ArgumentError('AES-256 key must be exactly 32 bytes (256 bits)');
    }
    if (nonce.length != 12) {
      throw ArgumentError('AES-GCM nonce must be exactly 12 bytes (96 bits)');
    }

    final secretKey = SecretKey(key);
    final secretBox = await _algorithm.encrypt(
      plaintext,
      secretKey: secretKey,
      nonce: nonce,
      aad: associatedData ?? <int>[],
    );

    return EncryptedPayload(
      nonce: Uint8List.fromList(secretBox.nonce),
      ciphertext: Uint8List.fromList(secretBox.cipherText),
      mac: Uint8List.fromList(secretBox.mac.bytes),
    );
  }

  /// Decrypts [encryptedMessage] and authenticates with [associatedData].
  /// Throws an exception if ciphertext, key, nonce, or associatedData has been tampered with.
  Future<Uint8List> decrypt({
    required EncryptedPayload encryptedMessage,
    required List<int> key,
    List<int>? associatedData,
  }) async {
    if (key.length != 32) {
      throw ArgumentError('AES-256 key must be exactly 32 bytes (256 bits)');
    }
    if (encryptedMessage.nonce.length != 12) {
      throw ArgumentError('AES-GCM nonce must be exactly 12 bytes');
    }

    final secretKey = SecretKey(key);
    final secretBox = SecretBox(
      encryptedMessage.ciphertext,
      nonce: encryptedMessage.nonce,
      mac: Mac(encryptedMessage.mac),
    );

    final cleartext = await _algorithm.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: associatedData ?? <int>[],
    );

    return Uint8List.fromList(cleartext);
  }
}
