import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:app/auth/device_key.dart';
import 'package:app/crypto/asymmetric.dart';
import 'package:app/crypto/envelope.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:web_socket_channel/web_socket_channel.dart';

const secretPlaintextContent = 'SECURECHAT_TOP_SECRET_E2E_MESSAGE_772183';

void main() {
  test('E2E: Two clients register, login, exchange E2EE messages and ack via real server', () async {
    final serverUrl = Platform.environment['SECURECHAT_SERVER_URL'] ?? 'http://127.0.0.1:8000';
    final invite1 = Platform.environment['SECURECHAT_INVITE_1'] ?? 'INV-1';
    final invite2 = Platform.environment['SECURECHAT_INVITE_2'] ?? 'INV-2';

    final uri = Uri.parse(serverUrl);
    final wsScheme = uri.scheme == 'https' ? 'wss' : 'ws';
    final wsBaseUrl = '$wsScheme://${uri.host}:${uri.port}';

    final rsa = RsaOaep();
    final signer = MessageSigner();

    // 1. Generate keys for Alice and Bob
    final aliceDevKey = SoftwareDeviceKey.generate(allowInReleaseForTesting: true);
    final aliceSigning = await signer.generateKeyPair();
    final aliceSigningPub = await signer.getPublicKeyBytes(aliceSigning);

    final bobDevKey = SoftwareDeviceKey.generate(allowInReleaseForTesting: true);
    final bobRsa = await rsa.generateKeyPair();

    // 2. Register Alice with invite1
    final aliceDevPubPem = await aliceDevKey.getPublicKeyPem();
    final regAliceResp = await http.post(
      Uri.parse('$serverUrl/register'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode({
        'invite_code': invite1,
        'user_id': 'e2e_alice',
        'device_id': 'alice_dev_1',
        'device_signing_pub': aliceDevPubPem,
        'device_encryption_pub': 'alice_rsa_pem',
      }),
    );
    expect(regAliceResp.statusCode, equals(200), reason: 'Alice registration failed: ${regAliceResp.body}');

    // 3. Register Bob with invite2
    final bobDevPubPem = await bobDevKey.getPublicKeyPem();
    final regBobResp = await http.post(
      Uri.parse('$serverUrl/register'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode({
        'invite_code': invite2,
        'user_id': 'e2e_bob',
        'device_id': 'bob_dev_1',
        'device_signing_pub': bobDevPubPem,
        'device_encryption_pub': 'bob_rsa_pem',
      }),
    );
    expect(regBobResp.statusCode, equals(200), reason: 'Bob registration failed: ${regBobResp.body}');

    // 4. Log in Alice via challenge-response
    final chalAliceResp = await http.post(
      Uri.parse('$serverUrl/auth/challenge'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode({'user_id': 'e2e_alice', 'device_id': 'alice_dev_1'}),
    );
    expect(chalAliceResp.statusCode, equals(200));
    final aliceNonce = (json.decode(chalAliceResp.body) as Map<String, dynamic>)['nonce'] as String;
    final aliceSig = await aliceDevKey.sign(Uint8List.fromList(utf8.encode(aliceNonce)));

    final verAliceResp = await http.post(
      Uri.parse('$serverUrl/auth/verify'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode({
        'user_id': 'e2e_alice',
        'device_id': 'alice_dev_1',
        'nonce': aliceNonce,
        'signature': aliceSig,
      }),
    );
    expect(verAliceResp.statusCode, equals(200));
    final aliceToken = (json.decode(verAliceResp.body) as Map<String, dynamic>)['access_token'] as String;

    // 5. Log in Bob via challenge-response
    final chalBobResp = await http.post(
      Uri.parse('$serverUrl/auth/challenge'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode({'user_id': 'e2e_bob', 'device_id': 'bob_dev_1'}),
    );
    expect(chalBobResp.statusCode, equals(200));
    final bobNonce = (json.decode(chalBobResp.body) as Map<String, dynamic>)['nonce'] as String;
    final bobSig = await bobDevKey.sign(Uint8List.fromList(utf8.encode(bobNonce)));

    final verBobResp = await http.post(
      Uri.parse('$serverUrl/auth/verify'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode({
        'user_id': 'e2e_bob',
        'device_id': 'bob_dev_1',
        'nonce': bobNonce,
        'signature': bobSig,
      }),
    );
    expect(verBobResp.statusCode, equals(200));
    final bobToken = (json.decode(verBobResp.body) as Map<String, dynamic>)['access_token'] as String;

    // 6. Connect Bob to WebSocket
    final bobWs = WebSocketChannel.connect(Uri.parse('$wsBaseUrl/ws?token=$bobToken'));
    final bobReceivedCompleter = Completer<Map<String, dynamic>>();

    final bobSub = bobWs.stream.listen((message) {
      final data = json.decode(message as String) as Map<String, dynamic>;
      if (data['type'] == 'message' && data['message_id'] == 'msg_e2e_101') {
        bobReceivedCompleter.complete(data);
      }
    });

    // Wait slightly for WebSocket handshake
    await Future<void>.delayed(const Duration(milliseconds: 300));

    // 7. Alice seals E2EE message for Bob
    final timestamp = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final envelopeBytes = await MessageEnvelope.seal(
      senderId: 'e2e_alice',
      recipientId: 'e2e_bob',
      messageId: 'msg_e2e_101',
      timestamp: timestamp,
      plaintext: utf8.encode(secretPlaintextContent),
      recipientRsaPublicKey: bobRsa.publicKey,
      senderSigningKeyPair: aliceSigning,
    );

    // 8. Alice connects to WebSocket and sends sealed ciphertext
    final aliceWs = WebSocketChannel.connect(Uri.parse('$wsBaseUrl/ws?token=$aliceToken'));
    await Future<void>.delayed(const Duration(milliseconds: 200));

    aliceWs.sink.add(json.encode({
      'action': 'send',
      'recipient_id': 'e2e_bob',
      'message_id': 'msg_e2e_101',
      'ciphertext_b64': base64.encode(envelopeBytes),
    }));

    // 9. Bob receives the frame over WebSocket
    final receivedFrame = await bobReceivedCompleter.future.timeout(const Duration(seconds: 10));
    expect(receivedFrame['sender_id'], equals('e2e_alice'));
    expect(receivedFrame['message_id'], equals('msg_e2e_101'));

    // 10. Bob opens (decrypts and verifies) the envelope
    final receivedCtB64 = receivedFrame['ciphertext_b64'] as String;
    final receivedEnvelopeBytes = base64.decode(receivedCtB64);

    final decryptedPlaintextBytes = await MessageEnvelope.open(
      envelopeBytes: receivedEnvelopeBytes,
      recipientId: 'e2e_bob',
      recipientRsaPrivateKey: bobRsa.privateKey,
      senderSigningPublicKey: aliceSigningPub,
      replayGuard: ReplayGuard(),
    );

    final decryptedText = utf8.decode(decryptedPlaintextBytes);
    expect(decryptedText, equals(secretPlaintextContent));

    // 11. Bob sends ack to delete the message from the server relay queue
    bobWs.sink.add(json.encode({
      'action': 'ack',
      'message_id': 'msg_e2e_101',
    }));

    await Future<void>.delayed(const Duration(milliseconds: 300));

    // Clean up
    await bobSub.cancel();
    await bobWs.sink.close();
    await aliceWs.sink.close();
  });
}
