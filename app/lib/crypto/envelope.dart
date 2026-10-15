import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:app/crypto/aes_gcm.dart';
import 'package:app/crypto/asymmetric.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pointycastle/export.dart';

class ReplayAttackException implements Exception {
  final String message;
  ReplayAttackException(this.message);
  @override
  String toString() => 'ReplayAttackException: $message';
}

class RecipientMismatchException implements Exception {
  final String message;
  RecipientMismatchException(this.message);
  @override
  String toString() => 'RecipientMismatchException: $message';
}

class ClockSkewException implements Exception {
  final String message;
  ClockSkewException(this.message);
  @override
  String toString() => 'ClockSkewException: $message';
}

class EnvelopeAuthenticationException implements Exception {
  final String message;
  EnvelopeAuthenticationException(this.message);
  @override
  String toString() => 'EnvelopeAuthenticationException: $message';
}

/// In-memory replay guard tracking recently processed message IDs.
class ReplayGuard {
  final Set<String> _seenMessageIds = <String>{};

  bool isSeen(String messageId) => _seenMessageIds.contains(messageId);

  void record(String messageId) {
    _seenMessageIds.add(messageId);
  }
}

/// Protocol v1 Message Envelope implementation combining AES-256-GCM, RSA-2048 OAEP, and Ed25519.
class MessageEnvelope {
  static const int protocolVersion = 0x01;
  static const int maxClockSkewSeconds = 300;

  static final RsaOaep _rsa = RsaOaep();
  static final AesGcmCipher _aes = AesGcmCipher();
  static final MessageSigner _signer = MessageSigner();
  static final Random _random = Random.secure();

  /// Seals a plaintext payload into an encrypted, signed binary envelope.
  static Future<Uint8List> seal({
    required String senderId,
    required String recipientId,
    required String messageId,
    required int timestamp,
    required List<int> plaintext,
    required RSAPublicKey recipientRsaPublicKey,
    required crypto.SimpleKeyPair senderSigningKeyPair,
  }) async {
    // 1. Generate fresh 32-byte AES key
    final aesKey = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      aesKey[i] = _random.nextInt(256);
    }

    // 2. Wrap 32-byte AES key using recipient's RSA-2048 public key
    final wrappedKey = _rsa.wrapKey(
      publicKey: recipientRsaPublicKey,
      aesKey: aesKey,
    );

    // 3. Construct canonical Associated Data (AAD)
    final aad = utf8.encode('$senderId:$recipientId:$messageId:$timestamp');

    // 4. Encrypt plaintext with AES-256-GCM
    final enc = await _aes.encrypt(
      plaintext: plaintext,
      key: aesKey,
      associatedData: aad,
    );

    // 5. Serialize envelope body (everything except the trailing signature)
    final senderBytes = utf8.encode(senderId);
    final recipientBytes = utf8.encode(recipientId);
    final messageIdBytes = utf8.encode(messageId);

    final builder = BytesBuilder();
    builder.addByte(protocolVersion);

    builder.addByte(senderBytes.length);
    builder.add(senderBytes);

    builder.addByte(recipientBytes.length);
    builder.add(recipientBytes);

    builder.addByte(messageIdBytes.length);
    builder.add(messageIdBytes);

    // 8 bytes timestamp (big endian)
    final tsData = ByteData(8);
    tsData.setInt64(0, timestamp, Endian.big);
    builder.add(tsData.buffer.asUint8List());

    // 256 bytes wrapped key
    builder.add(wrappedKey);

    // 12 bytes nonce
    builder.add(enc.nonce);

    // 16 bytes MAC tag
    builder.add(enc.mac);

    // 4 bytes ciphertext length + ciphertext
    final ctLenData = ByteData(4);
    ctLenData.setUint32(0, enc.ciphertext.length, Endian.big);
    builder.add(ctLenData.buffer.asUint8List());
    builder.add(enc.ciphertext);

    final envelopeBody = builder.toBytes();

    // 6. Sign the envelope body with sender's Ed25519 signing key
    final signature = await _signer.sign(
      keyPair: senderSigningKeyPair,
      message: envelopeBody,
    );

    // 7. Append 64-byte signature to the envelope
    final fullEnvelope = BytesBuilder();
    fullEnvelope.add(envelopeBody);
    fullEnvelope.add(signature);

    return fullEnvelope.toBytes();
  }

  /// Opens an encrypted binary envelope, verifying signatures, recipient, replay, and authenticity.
  static Future<Uint8List> open({
    required Uint8List envelopeBytes,
    required String recipientId,
    required Uint8List senderSigningPublicKey,
    required RSAPrivateKey recipientRsaPrivateKey,
    required ReplayGuard replayGuard,
    int? currentTimestamp,
    int maxClockSkew = maxClockSkewSeconds,
  }) async {
    if (envelopeBytes.length < 1 + 1 + 1 + 1 + 8 + 256 + 12 + 16 + 4 + 64) {
      throw EnvelopeAuthenticationException('Envelope too short to be valid');
    }

    final byteData = ByteData.sublistView(envelopeBytes);
    var offset = 0;

    final version = byteData.getUint8(offset++);
    if (version != protocolVersion) {
      throw EnvelopeAuthenticationException('Unsupported protocol version: $version');
    }

    final senderLen = byteData.getUint8(offset++);
    final senderId = utf8.decode(envelopeBytes.sublist(offset, offset + senderLen));
    offset += senderLen;

    final recipLen = byteData.getUint8(offset++);
    final parsedRecipientId = utf8.decode(envelopeBytes.sublist(offset, offset + recipLen));
    offset += recipLen;

    final msgIdLen = byteData.getUint8(offset++);
    final messageId = utf8.decode(envelopeBytes.sublist(offset, offset + msgIdLen));
    offset += msgIdLen;

    final timestamp = byteData.getInt64(offset, Endian.big);
    offset += 8;

    // 1. Recipient check
    if (parsedRecipientId != recipientId) {
      throw RecipientMismatchException(
        'Recipient mismatch: intended for $parsedRecipientId, received by $recipientId',
      );
    }

    // 2. Clock skew check
    final now = currentTimestamp ?? (DateTime.now().millisecondsSinceEpoch ~/ 1000);
    if ((timestamp - now).abs() > maxClockSkew) {
      throw ClockSkewException(
        'Timestamp outside allowed clock skew ($timestamp vs $now, diff: ${(timestamp - now).abs()}s)',
      );
    }

    // 3. Replay guard check
    if (replayGuard.isSeen(messageId)) {
      throw ReplayAttackException('Replay detected for messageId: $messageId');
    }

    final wrappedKey = Uint8List.fromList(envelopeBytes.sublist(offset, offset + 256));
    offset += 256;

    final nonce = Uint8List.fromList(envelopeBytes.sublist(offset, offset + 12));
    offset += 12;

    final mac = Uint8List.fromList(envelopeBytes.sublist(offset, offset + 16));
    offset += 16;

    final ctLen = byteData.getUint32(offset, Endian.big);
    offset += 4;

    if (offset + ctLen + 64 != envelopeBytes.length) {
      throw EnvelopeAuthenticationException('Envelope length mismatch');
    }

    final ciphertext = Uint8List.fromList(envelopeBytes.sublist(offset, offset + ctLen));
    offset += ctLen;

    final signature = Uint8List.fromList(envelopeBytes.sublist(offset, offset + 64));

    // 4. Verify Ed25519 digital signature over envelope body [0 .. end of ciphertext]
    final envelopeBody = envelopeBytes.sublist(0, offset);
    final isValidSig = await _signer.verify(
      publicKeyBytes: senderSigningPublicKey,
      message: envelopeBody,
      signatureBytes: signature,
    );

    if (!isValidSig) {
      throw EnvelopeAuthenticationException('Invalid digital signature on envelope');
    }

    // Mark message as seen in replay guard
    replayGuard.record(messageId);

    // 5. Unwrap AES key using recipient's RSA-2048 private key
    final aesKey = _rsa.unwrapKey(
      privateKey: recipientRsaPrivateKey,
      wrappedKey: wrappedKey,
    );

    // 6. Decrypt ciphertext with AES-256-GCM and verify AAD
    final aad = utf8.encode('$senderId:$recipientId:$messageId:$timestamp');
    final encryptedPayload = EncryptedPayload(
      nonce: nonce,
      ciphertext: ciphertext,
      mac: mac,
    );

    try {
      final decrypted = await _aes.decrypt(
        encryptedMessage: encryptedPayload,
        key: aesKey,
        associatedData: aad,
      );
      return decrypted;
    } catch (e) {
      throw EnvelopeAuthenticationException('AES-GCM decryption / tag verification failed: $e');
    }
  }
}
