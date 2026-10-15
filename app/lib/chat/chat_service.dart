import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:app/crypto/envelope.dart';
import 'package:app/storage/encrypted_message_store.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pointycastle/export.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

enum ChatConnectionState { disconnected, connecting, connected }

typedef WebSocketFactory = WebSocketChannel Function(Uri uri);

class ChatService {
  final String wsBaseUrl;
  final String Function() getAccessToken;
  final String myUserId;
  final crypto.SimpleKeyPair mySigningKeyPair;
  final RSAPrivateKey myRsaPrivateKey;
  final EncryptedMessageStore messageStore;
  final ReplayGuard replayGuard;
  final WebSocketFactory _wsFactory;

  WebSocketChannel? _channel;
  StreamSubscription<dynamic>? _subscription;
  Timer? _reconnectTimer;
  int _reconnectAttempts = 0;
  bool _isDisposed = false;

  ChatConnectionState _connectionState = ChatConnectionState.disconnected;
  ChatConnectionState get connectionState => _connectionState;

  final List<Map<String, dynamic>> _offlineQueue = [];
  final StreamController<ChatMessage> _incomingController = StreamController<ChatMessage>.broadcast(sync: true);
  final StreamController<ChatConnectionState> _stateController =
      StreamController<ChatConnectionState>.broadcast(sync: true);

  Stream<ChatMessage> get incomingMessages => _incomingController.stream;
  Stream<ChatMessage> get messageStream => _incomingController.stream;
  Stream<ChatConnectionState> get connectionStateStream => _stateController.stream;

  /// Dispatches an incoming ChatMessage directly to listeners.
  void dispatchIncomingMessage(ChatMessage message) {
    if (!_incomingController.isClosed) {
      _incomingController.add(message);
    }
  }

  // Contact key resolvers for incoming message verification
  final Future<Uint8List?> Function(String senderId) getSenderSigningPublicKey;

  ChatService({
    required this.wsBaseUrl,
    required this.getAccessToken,
    required this.myUserId,
    required this.mySigningKeyPair,
    required this.myRsaPrivateKey,
    required this.messageStore,
    required this.getSenderSigningPublicKey,
    ReplayGuard? replayGuard,
    WebSocketFactory? wsFactory,
  })  : replayGuard = replayGuard ?? ReplayGuard(),
        _wsFactory = wsFactory ?? WebSocketChannel.connect;

  /// Connects to WebSocket server.
  void connect() {
    if (_isDisposed) return;
    if (_connectionState == ChatConnectionState.connected ||
        _connectionState == ChatConnectionState.connecting) {
      return;
    }

    _updateState(ChatConnectionState.connecting);

    try {
      final token = getAccessToken();
      final uri = Uri.parse('$wsBaseUrl/ws?token=$token');
      _channel = _wsFactory(uri);

      _subscription = _channel!.stream.listen(
        _onMessageReceived,
        onDone: _onDisconnected,
        onError: (err) => _onDisconnected(),
        cancelOnError: true,
      );

      _updateState(ChatConnectionState.connected);
      _reconnectAttempts = 0;
      _flushOfflineQueue();
    } catch (_) {
      _onDisconnected();
    }
  }

  void _updateState(ChatConnectionState state) {
    _connectionState = state;
    if (!_stateController.isClosed) {
      _stateController.add(state);
    }
  }

  void _onDisconnected() {
    _subscription?.cancel();
    _subscription = null;
    _channel = null;
    _updateState(ChatConnectionState.disconnected);

    if (!_isDisposed) {
      _scheduleReconnect();
    }
  }

  void _scheduleReconnect() {
    _reconnectTimer?.cancel();
    // Exponential backoff: 1s, 2s, 4s, 8s, up to 30s
    final delaySeconds = (1 << _reconnectAttempts).clamp(1, 30);
    _reconnectAttempts++;

    _reconnectTimer = Timer(Duration(seconds: delaySeconds), () {
      if (!_isDisposed && _connectionState == ChatConnectionState.disconnected) {
        connect();
      }
    });
  }

  Future<void> _flushOfflineQueue() async {
    if (_connectionState != ChatConnectionState.connected || _channel == null) return;

    final queueCopy = List<Map<String, dynamic>>.from(_offlineQueue);
    _offlineQueue.clear();

    for (final payload in queueCopy) {
      try {
        _channel!.sink.add(json.encode(payload));
      } catch (_) {
        _offlineQueue.add(payload);
        _onDisconnected();
        break;
      }
    }
  }

  /// Sends a plaintext message: seals it into an authenticated envelope, stores locally, and relays.
  Future<ChatMessage> sendMessage({
    required String recipientId,
    required String text,
    required RSAPublicKey recipientRsaPublicKey,
  }) async {
    final timestamp = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final messageId = 'msg_${timestamp}_${DateTime.now().microsecondsSinceEpoch % 1000000}';
    final conversationId = recipientId;

    // 1. Seal envelope
    final envelopeBytes = await MessageEnvelope.seal(
      senderId: myUserId,
      recipientId: recipientId,
      messageId: messageId,
      timestamp: timestamp,
      plaintext: utf8.encode(text),
      recipientRsaPublicKey: recipientRsaPublicKey,
      senderSigningKeyPair: mySigningKeyPair,
    );

    final ctB64 = base64.encode(envelopeBytes);

    // 2. Store locally with 'sending' status
    final chatMsg = ChatMessage(
      id: messageId,
      conversationId: conversationId,
      senderId: myUserId,
      recipientId: recipientId,
      content: text,
      timestamp: timestamp,
      isOutgoing: true,
      status: 'sending',
    );
    await messageStore.saveMessage(chatMsg);

    // 3. Queue / send via WebSocket
    final payload = {
      'action': 'send',
      'recipient_id': recipientId,
      'message_id': messageId,
      'ciphertext_b64': ctB64,
    };

    if (_connectionState == ChatConnectionState.connected && _channel != null) {
      try {
        _channel!.sink.add(json.encode(payload));
        // Mark as sent
        final sentMsg = ChatMessage(
          id: messageId,
          conversationId: conversationId,
          senderId: myUserId,
          recipientId: recipientId,
          content: text,
          timestamp: timestamp,
          isOutgoing: true,
          status: 'sent',
        );
        await messageStore.saveMessage(sentMsg);
        return sentMsg;
      } catch (_) {
        _offlineQueue.add(payload);
        _onDisconnected();
      }
    } else {
      _offlineQueue.add(payload);
    }

    return chatMsg;
  }

  /// Handles incoming WebSocket frames: verification, opening, local storage, and ack.
  Future<void> _onMessageReceived(dynamic frame) async {
    try {
      final data = json.decode(frame as String) as Map<String, dynamic>;
      final type = data['type'] as String?;

      if (type == 'message') {
        final messageId = data['message_id'] as String;
        final senderId = data['sender_id'] as String;
        final ctB64 = data['ciphertext_b64'] as String;
        final envelopeBytes = base64.decode(ctB64);

        // Fetch sender's signing public key
        final senderSigningPub = await getSenderSigningPublicKey(senderId);
        if (senderSigningPub == null) {
          throw StateError('Cannot verify message: unknown sender $senderId');
        }

        // Open & verify envelope
        final decryptedPlaintextBytes = await MessageEnvelope.open(
          envelopeBytes: envelopeBytes,
          recipientId: myUserId,
          senderSigningPublicKey: senderSigningPub,
          recipientRsaPrivateKey: myRsaPrivateKey,
          replayGuard: replayGuard,
        );

        final text = utf8.decode(decryptedPlaintextBytes);
        final timestamp = data['created_at'] as int? ?? (DateTime.now().millisecondsSinceEpoch ~/ 1000);

        final receivedMsg = ChatMessage(
          id: messageId,
          conversationId: senderId,
          senderId: senderId,
          recipientId: myUserId,
          content: text,
          timestamp: timestamp,
          isOutgoing: false,
          status: 'delivered',
        );

        // Store encrypted at rest locally
        await messageStore.saveMessage(receivedMsg);

        // Send delete-on-ack back to server
        _sendAck(messageId);

        // Emit to UI stream
        if (!_incomingController.isClosed) {
          _incomingController.add(receivedMsg);
        }
      } else if (data['status'] == 'ack_ok') {
        // Server confirmed message ack
      }
    } catch (_) {
      // Discard invalid / tampered messages
    }
  }

  void _sendAck(String messageId) {
    if (_connectionState == ChatConnectionState.connected && _channel != null) {
      try {
        _channel!.sink.add(json.encode({'action': 'ack', 'message_id': messageId}));
      } catch (_) {}
    }
  }

  void disconnect() {
    _reconnectTimer?.cancel();
    _subscription?.cancel();
    _subscription = null;
    _channel?.sink.close();
    _channel = null;
    _updateState(ChatConnectionState.disconnected);
  }

  void dispose() {
    _isDisposed = true;
    disconnect();
    _incomingController.close();
    _stateController.close();
  }
}
