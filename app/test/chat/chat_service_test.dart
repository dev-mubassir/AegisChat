import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:app/chat/chat_service.dart';
import 'package:app/crypto/asymmetric.dart';
import 'package:app/crypto/envelope.dart';
import 'package:app/crypto/keystore.dart';
import 'package:app/storage/encrypted_message_store.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:stream_channel/stream_channel.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

class FakeWebSocketChannel extends StreamChannelMixin<dynamic> implements WebSocketChannel {
  final StreamController<dynamic> _serverToClient = StreamController<dynamic>.broadcast(sync: true);
  final StreamController<dynamic> _clientToServer = StreamController<dynamic>(sync: true);

  Stream<dynamic> get clientStream => _clientToServer.stream;
  void pushFromServer(dynamic data) => _serverToClient.add(data);

  @override
  Stream<dynamic> get stream => _serverToClient.stream;

  @override
  WebSocketSink get sink => _FakeWebSocketSink(_clientToServer);

  @override
  int? get closeCode => null;

  @override
  String? get closeReason => null;

  @override
  String? get protocol => null;

  @override
  Future<void> get ready => Future.value();
}

class _FakeWebSocketSink implements WebSocketSink {
  final StreamController<dynamic> _controller;
  _FakeWebSocketSink(this._controller);

  @override
  void add(dynamic data) => _controller.add(data);

  @override
  void addError(Object error, [StackTrace? stackTrace]) =>
      _controller.addError(error, stackTrace);

  @override
  Future<void> addStream(Stream<dynamic> stream) => _controller.addStream(stream);

  @override
  Future<void> close([int? closeCode, String? closeReason]) => _controller.close();

  @override
  Future<void> get done => _controller.done;
}

void main() {
  group('ChatService', () {
    late Directory tempDir;
    late File dbFile;
    late InMemoryKeyStore keyStore;
    late EncryptedMessageStore messageStore;
    late RsaOaep rsa;
    late MessageSigner signer;

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('chat_service_test_');
      dbFile = File('${tempDir.path}/chat_test.enc');
      keyStore = InMemoryKeyStore();
      messageStore = EncryptedMessageStore(file: dbFile, keyStore: keyStore);
      rsa = RsaOaep();
      signer = MessageSigner();
    });

    tearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    test('send message seals envelope, saves locally, and sends via WebSocket', () async {
      final aliceRsa = await rsa.generateKeyPair();
      final bobRsa = await rsa.generateKeyPair();
      final aliceSigning = await signer.generateKeyPair();

      final fakeChannel = FakeWebSocketChannel();
      final sentFrames = <String>[];
      fakeChannel.clientStream.listen((data) => sentFrames.add(data as String));

      final chatService = ChatService(
        wsBaseUrl: 'ws://localhost:8000',
        getAccessToken: () => 'alice_token_123',
        myUserId: 'alice',
        mySigningKeyPair: aliceSigning,
        myRsaPrivateKey: aliceRsa.privateKey,
        messageStore: messageStore,
        getSenderSigningPublicKey: (id) async => null,
        wsFactory: (uri) {
          expect(uri.toString(), contains('token=alice_token_123'));
          return fakeChannel;
        },
      );

      chatService.connect();
      expect(chatService.connectionState, equals(ChatConnectionState.connected));

      final sentMsg = await chatService.sendMessage(
        recipientId: 'bob',
        text: 'Hello Bob over WebSocket!',
        recipientRsaPublicKey: bobRsa.publicKey,
      );

      expect(sentMsg.status, equals('sent'));
      expect(sentMsg.content, equals('Hello Bob over WebSocket!'));

      // Verify message was stored in local EncryptedMessageStore
      final storedMessages = await messageStore.getMessages('bob');
      expect(storedMessages.length, equals(1));
      expect(storedMessages.first.content, equals('Hello Bob over WebSocket!'));
      expect(storedMessages.first.status, equals('sent'));

      // Verify frame sent over WebSocket
      expect(sentFrames.length, equals(1));
      final frameJson = json.decode(sentFrames.first) as Map<String, dynamic>;
      expect(frameJson['action'], equals('send'));
      expect(frameJson['recipient_id'], equals('bob'));
      expect(frameJson['message_id'], equals(sentMsg.id));
      expect(frameJson['ciphertext_b64'], isNotEmpty);

      chatService.dispose();
    });

    test('offline queue stores messages and flushes upon reconnection', () async {
      final aliceRsa = await rsa.generateKeyPair();
      final bobRsa = await rsa.generateKeyPair();
      final aliceSigning = await signer.generateKeyPair();

      final fakeChannel = FakeWebSocketChannel();
      final sentFrames = <String>[];
      fakeChannel.clientStream.listen((data) => sentFrames.add(data as String));

      final chatService = ChatService(
        wsBaseUrl: 'ws://localhost:8000',
        getAccessToken: () => 'alice_token_123',
        myUserId: 'alice',
        mySigningKeyPair: aliceSigning,
        myRsaPrivateKey: aliceRsa.privateKey,
        messageStore: messageStore,
        getSenderSigningPublicKey: (id) async => null,
        wsFactory: (uri) => fakeChannel,
      );

      // Do NOT connect yet! (Offline)
      final offlineMsg = await chatService.sendMessage(
        recipientId: 'bob',
        text: 'Queued message sent while offline',
        recipientRsaPublicKey: bobRsa.publicKey,
      );

      expect(offlineMsg.status, equals('sending'));
      expect(sentFrames.isEmpty, isTrue);

      // Now connect to WebSocket -> should flush queued message!
      chatService.connect();
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(sentFrames.length, equals(1));
      final flushedFrame = json.decode(sentFrames.first) as Map<String, dynamic>;
      expect(flushedFrame['message_id'], equals(offlineMsg.id));

      chatService.dispose();
    });

    test('receiving message opens envelope, stores locally, sends ack, and emits to stream',
        () async {
      final bobRsa = await rsa.generateKeyPair();
      final aliceSigning = await signer.generateKeyPair();
      final alicePubSigning = await signer.getPublicKeyBytes(aliceSigning);

      final fakeChannel = FakeWebSocketChannel();
      final clientAcks = <String>[];
      fakeChannel.clientStream.listen((data) => clientAcks.add(data as String));

      // Bob's chat service
      final bobChatService = ChatService(
        wsBaseUrl: 'ws://localhost:8000',
        getAccessToken: () => 'bob_token_456',
        myUserId: 'bob',
        mySigningKeyPair: await signer.generateKeyPair(),
        myRsaPrivateKey: bobRsa.privateKey,
        messageStore: messageStore,
        getSenderSigningPublicKey: (senderId) async {
          if (senderId == 'alice') return alicePubSigning;
          return null;
        },
        wsFactory: (uri) => fakeChannel,
      );

      bobChatService.connect();

      // Alice seals a message for Bob
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final sealedEnvelope = await MessageEnvelope.seal(
        senderId: 'alice',
        recipientId: 'bob',
        messageId: 'msg_recv_999',
        timestamp: now,
        plaintext: utf8.encode('Hi Bob, this is secret Alice!'),
        recipientRsaPublicKey: bobRsa.publicKey,
        senderSigningKeyPair: aliceSigning,
      );

      final incomingCompleter = Completer<ChatMessage>();
      bobChatService.incomingMessages.listen((msg) {
        incomingCompleter.complete(msg);
      });

      // Simulate incoming frame from WebSocket server
      fakeChannel.pushFromServer(json.encode({
        'type': 'message',
        'message_id': 'msg_recv_999',
        'sender_id': 'alice',
        'recipient_id': 'bob',
        'ciphertext_b64': base64.encode(sealedEnvelope),
        'created_at': now,
      }));

      final receivedMsg = await incomingCompleter.future;
      expect(receivedMsg.id, equals('msg_recv_999'));
      expect(receivedMsg.senderId, equals('alice'));
      expect(receivedMsg.content, equals('Hi Bob, this is secret Alice!'));
      expect(receivedMsg.isOutgoing, isFalse);

      // Verify stored in local database
      final stored = await messageStore.getMessages('alice');
      expect(stored.length, equals(1));
      expect(stored.first.content, equals('Hi Bob, this is secret Alice!'));

      // Verify delete-on-ack was sent back to server
      expect(clientAcks.length, equals(1));
      final ackJson = json.decode(clientAcks.first) as Map<String, dynamic>;
      expect(ackJson['action'], equals('ack'));
      expect(ackJson['message_id'], equals('msg_recv_999'));

      bobChatService.dispose();
    });
  });
}
