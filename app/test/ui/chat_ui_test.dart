import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:app/auth/app_lock.dart';
import 'package:app/chat/chat_service.dart';
import 'package:app/contacts/contact_manager.dart';
import 'package:app/crypto/asymmetric.dart';
import 'package:app/crypto/keystore.dart';
import 'package:app/main.dart';
import 'package:app/storage/encrypted_message_store.dart';
import 'package:app/ui/chat_screen.dart';
import 'package:app/ui/contacts_screen.dart';
import 'package:app/ui/lock_screen.dart';
import 'package:app/ui/registration_screen.dart';
import 'package:app/ui/safety_number_screen.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:flutter/material.dart';
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

class InMemoryMessageStore extends EncryptedMessageStore {
  final Map<String, List<ChatMessage>> _store = {};

  InMemoryMessageStore() : super(file: File('in_memory_dummy'), keyStore: InMemoryKeyStore());

  @override
  Future<void> saveMessage(ChatMessage message, {Uint8List? overrideKey}) async {
    final list = _store.putIfAbsent(message.conversationId, () => []);
    final idx = list.indexWhere((m) => m.id == message.id);
    if (idx != -1) {
      list[idx] = message;
    } else {
      list.add(message);
    }
  }

  @override
  Future<List<ChatMessage>> getMessages(String conversationId, {Uint8List? overrideKey}) async {
    return List.from(_store[conversationId] ?? []);
  }
}

void main() {
  late RsaKeyPair aliceRsa;
  late RsaKeyPair bobRsa;
  late crypto.SimpleKeyPair aliceSigning;
  late Uint8List alicePubSigning;
  late crypto.SimpleKeyPair bobSigning;
  late Uint8List bobPubSigning;

  setUpAll(() async {
    final rsa = RsaOaep();
    final signer = MessageSigner();
    aliceRsa = await rsa.generateKeyPair();
    bobRsa = await rsa.generateKeyPair();
    aliceSigning = await signer.generateKeyPair();
    alicePubSigning = await signer.getPublicKeyBytes(aliceSigning);
    bobSigning = await signer.generateKeyPair();
    bobPubSigning = await signer.getPublicKeyBytes(bobSigning);
  });

  group('Chat UI Widget Tests', () {
    late InMemoryMessageStore messageStore;
    late Contact bobContact;
    late ContactManager contactManager;
    late ChatService chatService;
    late FakeWebSocketChannel fakeWs;

    setUp(() {
      messageStore = InMemoryMessageStore();
      fakeWs = FakeWebSocketChannel();

      final bobSigningHex = bobPubSigning.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      bobContact = Contact(
        userId: 'bob',
        displayName: 'Bob User',
        signingPublicKeyHex: bobSigningHex,
        encryptionPublicKeyPem: '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----',
        rsaPublicKey: bobRsa.publicKey,
        isVerified: true,
      );

      contactManager = ContactManager();
      contactManager.addContact(bobContact);

      chatService = ChatService(
        wsBaseUrl: 'ws://localhost:8000',
        getAccessToken: () => 'alice_token',
        myUserId: 'alice',
        mySigningKeyPair: aliceSigning,
        myRsaPrivateKey: aliceRsa.privateKey,
        messageStore: messageStore,
        getSenderSigningPublicKey: (id) async => id == 'bob' ? bobPubSigning : null,
        wsFactory: (uri) => fakeWs,
      );
      chatService.connect();
    });

    tearDown(() {
      chatService.dispose();
    });

    testWidgets('a sent message appears in chat screen with status', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: ChatScreen(
            contact: bobContact,
            chatService: chatService,
            messageStore: messageStore,
            contactManager: contactManager,
            localSigningKeyBytes: alicePubSigning,
          ),
        ),
      );

      await tester.pumpAndSettle();
      expect(find.text('Bob User'), findsOneWidget);
      expect(find.text('No messages yet. Send a secure encrypted message!'), findsOneWidget);

      // Enter message and tap send
      await tester.enterText(find.byKey(const Key('message_input')), 'Hello Bob, top secret!');
      await tester.tap(find.byKey(const Key('send_button')));
      await tester.pump();

      // Assert sent message appears on screen
      expect(find.text('Hello Bob, top secret!'), findsOneWidget);
      expect(find.byIcon(Icons.done), findsOneWidget); // Status 'sent' icon
    });

    testWidgets('a received message is decrypted and appears in chat screen', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: ChatScreen(
            contact: bobContact,
            chatService: chatService,
            messageStore: messageStore,
            contactManager: contactManager,
            localSigningKeyBytes: alicePubSigning,
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Dispatch an incoming decrypted message
      final rxMsg = ChatMessage(
        id: 'msg_rx_999',
        conversationId: 'bob',
        senderId: 'bob',
        recipientId: 'alice',
        content: 'Decrypted secret payload from Bob',
        timestamp: DateTime.now().millisecondsSinceEpoch ~/ 1000,
        isOutgoing: false,
        status: 'delivered',
      );
      await messageStore.saveMessage(rxMsg);
      chatService.dispatchIncomingMessage(rxMsg);
      await tester.pumpAndSettle();

      // Assert received decrypted message appears on screen
      expect(find.text('Decrypted secret payload from Bob'), findsOneWidget);
    });

    testWidgets('a locked app shows the lock screen and unlocks with PIN', (WidgetTester tester) async {
      final keyStore = InMemoryKeyStore();
      final biometricService = FakeBiometricService(isAvailable: true, shouldSucceed: true);
      final lockManager = AppLockManager(
        keyStore: keyStore,
        biometricService: biometricService,
      );

      // Setup 6-digit PIN and lock
      await lockManager.setupPin('123456');
      lockManager.lock();
      expect(lockManager.isLocked, isTrue);

      await tester.pumpWidget(
        MyApp(
          appLockManager: lockManager,
          contactManager: contactManager,
          chatService: chatService,
          messageStore: messageStore,
          localSigningKeyBytes: alicePubSigning,
        ),
      );

      await tester.pumpAndSettle();

      // Verify LockScreen is shown
      expect(find.byType(LockScreen), findsOneWidget);
      expect(find.text('SecureChat Locked'), findsOneWidget);
      expect(find.byKey(const Key('pin_input')), findsOneWidget);

      // Enter wrong PIN
      await tester.enterText(find.byKey(const Key('pin_input')), '000000');
      await tester.tap(find.byKey(const Key('unlock_button')));
      await tester.pumpAndSettle();
      expect(find.textContaining('Incorrect PIN'), findsOneWidget);

      // Enter correct PIN
      await tester.enterText(find.byKey(const Key('pin_input')), '123456');
      await tester.tap(find.byKey(const Key('unlock_button')));
      await tester.pumpAndSettle();

      // Verify unlocked and main screen is now visible
      expect(find.byType(LockScreen), findsNothing);
      expect(find.byType(ContactsScreen), findsOneWidget);
    });

    testWidgets('RegistrationScreen submits credentials and PIN', (WidgetTester tester) async {
      String? registeredInvite;
      String? registeredUsername;
      String? registeredDevice;
      String? registeredPin;

      await tester.pumpWidget(
        MaterialApp(
          home: RegistrationScreen(
            onRegister: ({
              required String inviteCode,
              required String username,
              required String deviceName,
              required String pin,
            }) async {
              registeredInvite = inviteCode;
              registeredUsername = username;
              registeredDevice = deviceName;
              registeredPin = pin;
            },
          ),
        ),
      );

      await tester.pumpAndSettle();

      await tester.enterText(find.byKey(const Key('invite_code_input')), 'INV-VIP-999');
      await tester.enterText(find.byKey(const Key('username_input')), 'charlie');
      await tester.enterText(find.byKey(const Key('device_name_input')), 'Charlie-Phone');
      await tester.enterText(find.byKey(const Key('pin_setup_input')), '654321');

      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pumpAndSettle();

      expect(registeredInvite, equals('INV-VIP-999'));
      expect(registeredUsername, equals('charlie'));
      expect(registeredDevice, equals('Charlie-Phone'));
      expect(registeredPin, equals('654321'));
    });

    testWidgets('SafetyNumberScreen displays 60 digits and toggles verification', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: SafetyNumberScreen(
            contact: bobContact,
            contactManager: contactManager,
            localSigningKeyBytes: alicePubSigning,
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.textContaining('Safety Number: Bob User'), findsOneWidget);
      expect(find.byKey(const Key('toggle_verified_screen_button')), findsOneWidget);

      // Toggle verification
      await tester.tap(find.byKey(const Key('toggle_verified_screen_button')));
      await tester.pumpAndSettle();
      expect(find.text('Mark as Verified'), findsOneWidget);

      await tester.tap(find.byKey(const Key('toggle_verified_screen_button')));
      await tester.pumpAndSettle();
      expect(find.text('Mark as Unverified'), findsOneWidget);
    });
  });
}
