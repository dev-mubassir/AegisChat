import 'dart:io';
import 'dart:typed_data';

import 'package:app/contacts/contact_manager.dart';
import 'package:app/crypto/safety_number.dart';
import 'package:app/ui/contacts_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('ContactManager Unit Tests', () {
    late Directory tempDir;
    late File contactsFile;
    late ContactManager manager;
    final localKey = Uint8List.fromList(List.generate(32, (i) => i));

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('contacts_test_');
      contactsFile = File('${tempDir.path}/contacts.json');
      manager = ContactManager(file: contactsFile);
    });

    tearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    test('add contact from QR and compute symmetric safety number', () async {
      final keyB = Uint8List.fromList(List.generate(32, (i) => 255 - i));
      final keyBHex = keyB.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

      final payload = ContactQrPayload(
        userId: 'bob',
        displayName: 'Bob Smith',
        signingPublicKeyHex: keyBHex,
        encryptionPublicKeyPem: '-----BEGIN PUBLIC KEY-----\nRSA\n-----END PUBLIC KEY-----\n',
      );

      final contact = await manager.addOrUpdateFromQr(payload);
      expect(contact.userId, equals('bob'));
      expect(contact.displayName, equals('Bob Smith'));
      expect(contact.isVerified, isFalse);
      expect(contact.hasKeyChanged, isFalse);

      final safetyNumber = manager.computeSafetyNumber('bob', localKey);
      final expected = SafetyNumber.compute(localKey, keyB);
      expect(safetyNumber, equals(expected));
      expect(safetyNumber.split(' ').length, equals(12));
    });

    test('verifying contact updates flag and persists', () async {
      final keyHex = List.generate(32, (i) => 'aa').join();
      final payload = ContactQrPayload(
        userId: 'alice',
        displayName: 'Alice',
        signingPublicKeyHex: keyHex,
        encryptionPublicKeyPem: 'rsa_pem',
      );

      await manager.addOrUpdateFromQr(payload);
      expect(manager.getContact('alice')!.isVerified, isFalse);

      await manager.setVerified('alice', true);
      expect(manager.getContact('alice')!.isVerified, isTrue);

      // Reload from disk to verify persistence
      final newManager = ContactManager(file: contactsFile);
      await newManager.load();
      expect(newManager.getContact('alice')!.isVerified, isTrue);
    });

    test('SECURITY: key change alerts user and revokes verification', () async {
      final key1 = List.generate(32, (i) => '11').join();
      final key2 = List.generate(32, (i) => '22').join();

      final payload1 = ContactQrPayload(
        userId: 'charlie',
        displayName: 'Charlie',
        signingPublicKeyHex: key1,
        encryptionPublicKeyPem: 'rsa_1',
      );

      await manager.addOrUpdateFromQr(payload1);
      await manager.setVerified('charlie', true);
      expect(manager.getContact('charlie')!.isVerified, isTrue);
      expect(manager.getContact('charlie')!.hasKeyChanged, isFalse);

      // Charlie's phone key changes!
      final payload2 = ContactQrPayload(
        userId: 'charlie',
        displayName: 'Charlie New Phone',
        signingPublicKeyHex: key2,
        encryptionPublicKeyPem: 'rsa_2',
      );

      final updated = await manager.addOrUpdateFromQr(payload2);

      // Verification MUST be revoked and alert flag set
      expect(updated.isVerified, isFalse);
      expect(updated.hasKeyChanged, isTrue);
      expect(updated.previousKeyHex, equals(key1));
      expect(updated.signingPublicKeyHex, equals(key2));
    });
  });

  group('ContactsScreen Widget Tests', () {
    late ContactManager manager;
    final localKey = Uint8List.fromList(List.generate(32, (i) => i));

    setUp(() {
      manager = ContactManager();
    });

    testWidgets('displays contacts, opens safety dialog, and allows verification', (tester) async {
      final keyHex = List.generate(32, (i) => '33').join();
      final payload = ContactQrPayload(
        userId: 'dave',
        displayName: 'Dave',
        signingPublicKeyHex: keyHex,
        encryptionPublicKeyPem: 'pem',
      );
      await manager.addOrUpdateFromQr(payload);

      await tester.pumpWidget(
        MaterialApp(
          home: ContactsScreen(
            contactManager: manager,
            localSigningKeyBytes: localKey,
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('Dave'), findsOneWidget);
      expect(find.text('Unverified Contact'), findsOneWidget);

      await tester.tap(find.byKey(const Key('contact_tile_dave')));
      await tester.pumpAndSettle();

      expect(find.text('Safety Number: Dave'), findsOneWidget);
      expect(find.text('Status: Unverified'), findsOneWidget);

      // Tap Mark as Verified button
      await tester.tap(find.text('Mark as Verified'));
      await tester.pumpAndSettle();

      expect(find.text('Status: Verified'), findsOneWidget);
      expect(manager.getContact('dave')!.isVerified, isTrue);
    });

    testWidgets('shows security warning when key has changed', (tester) async {
      final key1 = List.generate(32, (i) => '44').join();
      final key2 = List.generate(32, (i) => '55').join();

      await manager.addOrUpdateFromQr(
        ContactQrPayload(
          userId: 'eve',
          displayName: 'Eve',
          signingPublicKeyHex: key1,
          encryptionPublicKeyPem: 'pem1',
        ),
      );

      // Key changes
      await manager.addOrUpdateFromQr(
        ContactQrPayload(
          userId: 'eve',
          displayName: 'Eve',
          signingPublicKeyHex: key2,
          encryptionPublicKeyPem: 'pem2',
        ),
      );

      await tester.pumpWidget(
        MaterialApp(
          home: ContactsScreen(
            contactManager: manager,
            localSigningKeyBytes: localKey,
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('SECURITY ALERT: Key changed!'), findsOneWidget);

      await tester.tap(find.byKey(const Key('contact_tile_eve')));
      await tester.pumpAndSettle();

      expect(find.textContaining('WARNING: Security keys have changed!'), findsOneWidget);
    });
  });
}
