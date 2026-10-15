// ignore_for_file: avoid_print
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:app/crypto/asymmetric.dart';
import 'package:app/crypto/envelope.dart';

String bytesToHex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

Uint8List hexToBytes(String hex) {
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

void main() async {
  final rsaOaep = RsaOaep();
  final signer = MessageSigner();
  final vectors = <Map<String, dynamic>>[];

  final testCases = [
    {
      'name': 'Dart -> Python standard ASCII test',
      'sender_id': 'user_alice_123',
      'recipient_id': 'user_bob_456',
      'message_id': 'msg_001_standard',
      'plaintext': 'Hello from Flutter client! End-to-end encryption works.',
    },
    {
      'name': 'Dart -> Python UTF-8 emojis and symbols test',
      'sender_id': 'alice_device_a',
      'recipient_id': 'bob_device_b',
      'message_id': 'msg_002_utf8',
      'plaintext': '🔐 SecureChat test with emojis: 🚀🌟🔒 and accents: éàçöü! 🛡️',
    },
    {
      'name': 'Dart -> Python multi-line payload test',
      'sender_id': 'charlie_1',
      'recipient_id': 'david_2',
      'message_id': 'msg_003_multiline',
      'plaintext': 'Line 1: Top secret\nLine 2: Zero logs\nLine 3: Verified crypto!',
    },
  ];

  for (final tc in testCases) {
    // Generate RSA keypair for recipient
    final rsaPair = await rsaOaep.generateKeyPair();
    // Generate Ed25519 keypair for sender
    final edPair = await signer.generateKeyPair();
    final edPubBytes = await signer.getPublicKeyBytes(edPair);
    final edPrivBytes = await edPair.extractPrivateKeyBytes();

    final timestamp = 1770000000;
    final plainBytes = utf8.encode(tc['plaintext']!);

    // Seal envelope
    final envelope = await MessageEnvelope.seal(
      senderId: tc['sender_id']!,
      recipientId: tc['recipient_id']!,
      messageId: tc['message_id']!,
      timestamp: timestamp,
      plaintext: plainBytes,
      recipientRsaPublicKey: rsaPair.publicKey,
      senderSigningKeyPair: edPair,
    );

    vectors.add({
      'name': tc['name'],
      'sender_id': tc['sender_id'],
      'recipient_id': tc['recipient_id'],
      'message_id': tc['message_id'],
      'timestamp': timestamp,
      'plaintext_utf8': tc['plaintext'],
      'recipient_rsa': {
        'n_hex': rsaPair.publicKey.modulus!.toRadixString(16),
        'e': rsaPair.publicKey.exponent!.toInt(),
        'd_hex': rsaPair.privateKey.exponent!.toRadixString(16),
        'p_hex': rsaPair.privateKey.p!.toRadixString(16),
        'q_hex': rsaPair.privateKey.q!.toRadixString(16),
      },
      'sender_ed25519': {
        'public_key_hex': bytesToHex(edPubBytes),
        'private_seed_hex': bytesToHex(edPrivBytes),
      },
      'envelope_hex': bytesToHex(envelope),
    });
  }

  final outDir = Directory('../docs');
  if (!outDir.existsSync()) {
    outDir.createSync(recursive: true);
  }

  final outFile = File('../docs/vectors.json');
  outFile.writeAsStringSync(
    const JsonEncoder.withIndent('  ').convert({'vectors': vectors}),
  );

  print('Successfully generated ${vectors.length} test vectors in docs/vectors.json');
}
