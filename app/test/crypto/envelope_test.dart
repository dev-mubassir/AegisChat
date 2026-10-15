import 'dart:convert';
import 'dart:typed_data';

import 'package:app/crypto/asymmetric.dart';
import 'package:app/crypto/envelope.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('Message Envelope (seal and open)', () {
    late RsaOaep rsa;
    late MessageSigner signer;
    late RsaKeyPair bobRsa;
    late dynamic aliceSigningKey;
    late Uint8List aliceSigningPub;

    setUp(() async {
      rsa = RsaOaep();
      signer = MessageSigner();
      bobRsa = await rsa.generateKeyPair();
      aliceSigningKey = await signer.generateKeyPair();
      aliceSigningPub = await signer.getPublicKeyBytes(aliceSigningKey);
    });

    test('round trip seal and open success', () async {
      final replayGuard = ReplayGuard();
      final plaintext = utf8.encode('Secret message from Alice to Bob!');
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;

      final sealedEnvelope = await MessageEnvelope.seal(
        senderId: 'alice',
        recipientId: 'bob',
        messageId: 'msg_roundtrip_1',
        timestamp: now,
        plaintext: plaintext,
        recipientRsaPublicKey: bobRsa.publicKey,
        senderSigningKeyPair: aliceSigningKey,
      );

      final opened = await MessageEnvelope.open(
        envelopeBytes: sealedEnvelope,
        recipientId: 'bob',
        senderSigningPublicKey: aliceSigningPub,
        recipientRsaPrivateKey: bobRsa.privateKey,
        replayGuard: replayGuard,
      );

      expect(opened, equals(plaintext));
      expect(utf8.decode(opened), equals('Secret message from Alice to Bob!'));
    });

    test('replay rejected by replay guard', () async {
      final replayGuard = ReplayGuard();
      final plaintext = utf8.encode('Message to be replayed');
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;

      final sealed = await MessageEnvelope.seal(
        senderId: 'alice',
        recipientId: 'bob',
        messageId: 'msg_replay_1',
        timestamp: now,
        plaintext: plaintext,
        recipientRsaPublicKey: bobRsa.publicKey,
        senderSigningKeyPair: aliceSigningKey,
      );

      // First open passes
      final first = await MessageEnvelope.open(
        envelopeBytes: sealed,
        recipientId: 'bob',
        senderSigningPublicKey: aliceSigningPub,
        recipientRsaPrivateKey: bobRsa.privateKey,
        replayGuard: replayGuard,
      );
      expect(first, equals(plaintext));

      // Second open of same message ID must be rejected as replay
      expect(
        () async => await MessageEnvelope.open(
          envelopeBytes: sealed,
          recipientId: 'bob',
          senderSigningPublicKey: aliceSigningPub,
          recipientRsaPrivateKey: bobRsa.privateKey,
          replayGuard: replayGuard,
        ),
        throwsA(isA<ReplayAttackException>()),
      );
    });

    test('wrong recipient rejected', () async {
      final replayGuard = ReplayGuard();
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;

      final sealed = await MessageEnvelope.seal(
        senderId: 'alice',
        recipientId: 'bob',
        messageId: 'msg_wrong_recip',
        timestamp: now,
        plaintext: utf8.encode('For Bob only'),
        recipientRsaPublicKey: bobRsa.publicKey,
        senderSigningKeyPair: aliceSigningKey,
      );

      // Carol attempts to open message intended for Bob
      expect(
        () async => await MessageEnvelope.open(
          envelopeBytes: sealed,
          recipientId: 'carol',
          senderSigningPublicKey: aliceSigningPub,
          recipientRsaPrivateKey: bobRsa.privateKey,
          replayGuard: replayGuard,
        ),
        throwsA(isA<RecipientMismatchException>()),
      );
    });

    test('clock skew rejected', () async {
      final replayGuard = ReplayGuard();
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final futureTime = now + 600; // 10 minutes in the future (skew > 300s)

      final sealedFuture = await MessageEnvelope.seal(
        senderId: 'alice',
        recipientId: 'bob',
        messageId: 'msg_future',
        timestamp: futureTime,
        plaintext: utf8.encode('Future message'),
        recipientRsaPublicKey: bobRsa.publicKey,
        senderSigningKeyPair: aliceSigningKey,
      );

      expect(
        () async => await MessageEnvelope.open(
          envelopeBytes: sealedFuture,
          recipientId: 'bob',
          senderSigningPublicKey: aliceSigningPub,
          recipientRsaPrivateKey: bobRsa.privateKey,
          replayGuard: replayGuard,
        ),
        throwsA(isA<ClockSkewException>()),
      );
    });

    test('tampering with any byte fails verification or decryption', () async {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final sealed = await MessageEnvelope.seal(
        senderId: 'alice',
        recipientId: 'bob',
        messageId: 'msg_tamper_test',
        timestamp: now,
        plaintext: utf8.encode('Tamper test string'),
        recipientRsaPublicKey: bobRsa.publicKey,
        senderSigningKeyPair: aliceSigningKey,
      );

      // Tamper various parts of envelope
      final indicesToTest = [
        0, // version
        1, // sender_id length or sender byte
        10, // header
        25, // timestamp byte
        40, // wrapped key byte
        290, // nonce
        305, // mac
        325, // ciphertext
        sealed.length - 1, // signature
      ];

      for (final idx in indicesToTest) {
        if (idx < sealed.length) {
          final tampered = Uint8List.fromList(sealed);
          tampered[idx] ^= 0x01;
          final replayGuard = ReplayGuard();

          expect(
            () async => await MessageEnvelope.open(
              envelopeBytes: tampered,
              recipientId: 'bob',
              senderSigningPublicKey: aliceSigningPub,
              recipientRsaPrivateKey: bobRsa.privateKey,
              replayGuard: replayGuard,
            ),
            throwsException,
            reason: 'Tampered byte at index $idx did not fail open()',
          );
        }
      }
    });
  });
}
