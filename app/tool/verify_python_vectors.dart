// ignore_for_file: avoid_print
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:app/crypto/envelope.dart';
import 'package:pointycastle/export.dart';

Uint8List hexToBytes(String hex) {
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

void main() async {
  final vectorsFile = File('../docs/python_vectors.json');
  if (!vectorsFile.existsSync()) {
    stderr.writeln('Error: docs/python_vectors.json does not exist');
    exit(1);
  }

  final data = json.decode(vectorsFile.readAsStringSync()) as Map<String, dynamic>;
  final vectors = data['vectors'] as List<dynamic>;

  print('Verifying ${vectors.length} Python vectors in Dart...');

  for (final v in vectors) {
    final name = v['name'] as String;
    final recipientId = v['recipient_id'] as String;
    final timestamp = v['timestamp'] as int;
    final expectedPlaintext = v['plaintext_utf8'] as String;

    final rsaData = v['recipient_rsa'] as Map<String, dynamic>;
    final privKey = RSAPrivateKey(
      BigInt.parse(rsaData['n_hex'] as String, radix: 16),
      BigInt.parse(rsaData['d_hex'] as String, radix: 16),
      BigInt.parse(rsaData['p_hex'] as String, radix: 16),
      BigInt.parse(rsaData['q_hex'] as String, radix: 16),
    );

    final edData = v['sender_ed25519'] as Map<String, dynamic>;
    final pubKeyBytes = hexToBytes(edData['public_key_hex'] as String);

    final envelopeBytes = hexToBytes(v['envelope_hex'] as String);

    final replayGuard = ReplayGuard();
    final decrypted = await MessageEnvelope.open(
      envelopeBytes: envelopeBytes,
      recipientId: recipientId,
      senderSigningPublicKey: pubKeyBytes,
      recipientRsaPrivateKey: privKey,
      replayGuard: replayGuard,
      currentTimestamp: timestamp,
    );

    final actualPlaintext = utf8.decode(decrypted);
    if (actualPlaintext != expectedPlaintext) {
      stderr.writeln('FAIL: $name - Plaintext mismatch!');
      stderr.writeln('Expected: $expectedPlaintext');
      stderr.writeln('Actual:   $actualPlaintext');
      exit(1);
    }

    print('PASS: $name');
  }

  print('All Python vectors successfully opened and verified by Dart!');
}
