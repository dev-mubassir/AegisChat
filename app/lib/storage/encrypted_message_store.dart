import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:app/crypto/aes_gcm.dart';
import 'package:app/crypto/keystore.dart';

class StorageDecryptionException implements Exception {
  final String message;
  StorageDecryptionException(this.message);
  @override
  String toString() => 'StorageDecryptionException: $message';
}

/// Represents a decrypted chat message in memory.
class ChatMessage {
  final String id;
  final String conversationId;
  final String senderId;
  final String recipientId;
  final String content;
  final int timestamp;
  final bool isOutgoing;
  final String status;

  ChatMessage({
    required this.id,
    required this.conversationId,
    required this.senderId,
    required this.recipientId,
    required this.content,
    required this.timestamp,
    required this.isOutgoing,
    this.status = 'sent',
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'conversation_id': conversationId,
        'sender_id': senderId,
        'recipient_id': recipientId,
        'content': content,
        'timestamp': timestamp,
        'is_outgoing': isOutgoing,
        'status': status,
      };

  factory ChatMessage.fromJson(Map<String, dynamic> json) => ChatMessage(
        id: json['id'] as String,
        conversationId: json['conversation_id'] as String,
        senderId: json['sender_id'] as String,
        recipientId: json['recipient_id'] as String,
        content: json['content'] as String,
        timestamp: json['timestamp'] as int,
        isOutgoing: json['is_outgoing'] as bool,
        status: json['status'] as String? ?? 'sent',
      );
}

/// Local message storage with per-record AES-256-GCM encryption at rest.
///
/// Encryption keys are securely managed via KeyStore and never written to plain storage.
class EncryptedMessageStore {
  final File file;
  final KeyStore keyStore;
  final AesGcmCipher _aes = AesGcmCipher();

  static const String keyStorageEncryptionKey = 'local_db_encryption_key';

  EncryptedMessageStore({
    required this.file,
    required this.keyStore,
  });

  /// Retrieves or generates a 32-byte AES storage key from KeyStore.
  Future<Uint8List> getOrCreateKey() async {
    final existing = await keyStore.read(keyStorageEncryptionKey);
    if (existing != null && existing.isNotEmpty) {
      return base64.decode(existing);
    }

    final rand = Random.secure();
    final newKey = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      newKey[i] = rand.nextInt(256);
    }

    await keyStore.write(keyStorageEncryptionKey, base64.encode(newKey));
    return newKey;
  }

  Uint8List _buildAad(String id, String conversationId, int timestamp) {
    return Uint8List.fromList(utf8.encode('$id:$conversationId:$timestamp'));
  }

  /// Appends or updates an encrypted chat message record.
  Future<void> saveMessage(ChatMessage message, {Uint8List? overrideKey}) async {
    final key = overrideKey ?? await getOrCreateKey();
    final plaintext = utf8.encode(json.encode(message.toJson()));
    final aad = _buildAad(message.id, message.conversationId, message.timestamp);

    final encrypted = await _aes.encrypt(
      plaintext: plaintext,
      key: key,
      associatedData: aad,
    );

    final record = {
      'id': message.id,
      'conversation_id': message.conversationId,
      'timestamp': message.timestamp,
      'nonce_b64': base64.encode(encrypted.nonce),
      'ciphertext_b64': base64.encode(encrypted.ciphertext),
      'mac_b64': base64.encode(encrypted.mac),
    };

    final records = await _readRawRecords();
    records.removeWhere((r) => r['id'] == message.id);
    records.add(record);

    await _writeRawRecords(records);
  }

  /// Reads and decrypts all messages for a given conversation.
  Future<List<ChatMessage>> getMessages(
    String conversationId, {
    Uint8List? overrideKey,
  }) async {
    final key = overrideKey ?? await getOrCreateKey();
    final rawRecords = await _readRawRecords();
    final messages = <ChatMessage>[];

    for (final r in rawRecords) {
      if (r['conversation_id'] != conversationId) continue;

      final id = r['id'] as String;
      final ts = r['timestamp'] as int;
      final nonce = base64.decode(r['nonce_b64'] as String);
      final ciphertext = base64.decode(r['ciphertext_b64'] as String);
      final mac = base64.decode(r['mac_b64'] as String);

      final aad = _buildAad(id, conversationId, ts);
      final payload = EncryptedPayload(nonce: nonce, ciphertext: ciphertext, mac: mac);

      try {
        final decryptedBytes = await _aes.decrypt(
          encryptedMessage: payload,
          key: key,
          associatedData: aad,
        );
        final map = json.decode(utf8.decode(decryptedBytes)) as Map<String, dynamic>;
        messages.add(ChatMessage.fromJson(map));
      } catch (e) {
        throw StorageDecryptionException(
          'Failed to decrypt message record $id with given key: $e',
        );
      }
    }

    messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    return messages;
  }

  /// Deletes a specific message by ID.
  Future<void> deleteMessage(String messageId) async {
    final records = await _readRawRecords();
    records.removeWhere((r) => r['id'] == messageId);
    await _writeRawRecords(records);
  }

  /// Deletes all stored records.
  Future<void> clear() async {
    if (await file.exists()) {
      await file.delete();
    }
  }

  Future<List<Map<String, dynamic>>> _readRawRecords() async {
    if (!await file.exists()) return [];
    try {
      final content = await file.readAsString();
      if (content.trim().isEmpty) return [];
      final decoded = json.decode(content) as List<dynamic>;
      return decoded.map((e) => Map<String, dynamic>.from(e as Map)).toList();
    } catch (_) {
      return [];
    }
  }

  Future<void> _writeRawRecords(List<Map<String, dynamic>> records) async {
    if (!await file.parent.exists()) {
      await file.parent.create(recursive: true);
    }
    await file.writeAsString(json.encode(records));
  }
}
