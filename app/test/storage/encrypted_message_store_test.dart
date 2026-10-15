import 'dart:io';
import 'dart:typed_data';

import 'package:app/crypto/keystore.dart';
import 'package:app/storage/encrypted_message_store.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('EncryptedMessageStore', () {
    late Directory tempDir;
    late File dbFile;
    late InMemoryKeyStore keyStore;
    late EncryptedMessageStore store;

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('securechat_test_db_');
      dbFile = File('${tempDir.path}/messages.enc');
      keyStore = InMemoryKeyStore();
      store = EncryptedMessageStore(file: dbFile, keyStore: keyStore);
    });

    tearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    test('round-trip save and get messages in order', () async {
      final msg1 = ChatMessage(
        id: 'msg-1',
        conversationId: 'conv-alice-bob',
        senderId: 'alice',
        recipientId: 'bob',
        content: 'Hello Bob! This is message 1.',
        timestamp: 1000,
        isOutgoing: true,
      );

      final msg2 = ChatMessage(
        id: 'msg-2',
        conversationId: 'conv-alice-bob',
        senderId: 'bob',
        recipientId: 'alice',
        content: 'Hey Alice! Message 2 received.',
        timestamp: 1005,
        isOutgoing: false,
      );

      await store.saveMessage(msg1);
      await store.saveMessage(msg2);

      final retrieved = await store.getMessages('conv-alice-bob');
      expect(retrieved.length, equals(2));
      expect(retrieved[0].id, equals('msg-1'));
      expect(retrieved[0].content, equals('Hello Bob! This is message 1.'));
      expect(retrieved[1].id, equals('msg-2'));
      expect(retrieved[1].content, equals('Hey Alice! Message 2 received.'));
    });

    test('SECURITY: raw file on disk contains ZERO plaintext markers', () async {
      const sensitiveMarker = 'CONFIDENTIAL_MARKER_98765_DO_NOT_LEAK';

      final msg = ChatMessage(
        id: 'msg-secret',
        conversationId: 'conv-secure',
        senderId: 'alice',
        recipientId: 'bob',
        content: 'Here is the sensitive payload: $sensitiveMarker',
        timestamp: 2000,
        isOutgoing: true,
      );

      await store.saveMessage(msg);

      // Verify file exists
      expect(await dbFile.exists(), isTrue);

      // Read raw bytes and raw string directly from disk
      final rawBytes = await dbFile.readAsBytes();
      final rawContent = await dbFile.readAsString();

      // The plaintext marker MUST NOT appear in the file on disk
      expect(rawContent.contains(sensitiveMarker), isFalse);
      expect(rawContent.contains('sensitive payload'), isFalse);

      // Verify ciphertext is present and decrypted properly with key
      final messages = await store.getMessages('conv-secure');
      expect(messages.single.content, contains(sensitiveMarker));
      expect(rawBytes.isNotEmpty, isTrue);
    });

    test('wrong key CANNOT read or decrypt the stored messages', () async {
      final msg = ChatMessage(
        id: 'msg-locked',
        conversationId: 'conv-classified',
        senderId: 'alice',
        recipientId: 'bob',
        content: 'Classified intelligence document',
        timestamp: 3000,
        isOutgoing: true,
      );

      await store.saveMessage(msg);

      // Create a completely different wrong 32-byte key
      final wrongKey = Uint8List.fromList(List.generate(32, (i) => (i + 42) % 256));

      expect(
        () => store.getMessages('conv-classified', overrideKey: wrongKey),
        throwsA(isA<StorageDecryptionException>()),
      );
    });

    test('tampering with record on disk causes decryption failure', () async {
      final msg = ChatMessage(
        id: 'msg-tamper',
        conversationId: 'conv-tamper',
        senderId: 'alice',
        recipientId: 'bob',
        content: 'Message before bit flip',
        timestamp: 4000,
        isOutgoing: true,
      );

      await store.saveMessage(msg);

      // Tamper with file on disk by corrupting a byte in the middle
      final fileStr = await dbFile.readAsString();
      // Replace a character in the base64 ciphertext
      final tamperedStr = fileStr.replaceFirst('A', 'B');
      await dbFile.writeAsString(tamperedStr);

      expect(
        () => store.getMessages('conv-tamper'),
        throwsA(isA<StorageDecryptionException>()),
      );
    });

    test('delete message removes record from storage', () async {
      final msg = ChatMessage(
        id: 'msg-to-delete',
        conversationId: 'conv-del',
        senderId: 'alice',
        recipientId: 'bob',
        content: 'Ephemeral chat message',
        timestamp: 5000,
        isOutgoing: true,
      );

      await store.saveMessage(msg);
      var list = await store.getMessages('conv-del');
      expect(list.length, equals(1));

      await store.deleteMessage('msg-to-delete');
      list = await store.getMessages('conv-del');
      expect(list.isEmpty, isTrue);
    });
  });
}
