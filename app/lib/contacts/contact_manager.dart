import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:app/crypto/safety_number.dart';

class KeyChangedException implements Exception {
  final String userId;
  KeyChangedException(this.userId);
  @override
  String toString() => 'KeyChangedException: Security keys for $userId have changed!';
}

class Contact {
  final String userId;
  final String displayName;
  final String signingPublicKeyHex;
  final String encryptionPublicKeyPem;
  bool isVerified;
  String? previousKeyHex;
  bool hasKeyChanged;

  Contact({
    required this.userId,
    required this.displayName,
    required this.signingPublicKeyHex,
    required this.encryptionPublicKeyPem,
    this.isVerified = false,
    this.previousKeyHex,
    this.hasKeyChanged = false,
  });

  Map<String, dynamic> toJson() => {
        'user_id': userId,
        'display_name': displayName,
        'signing_public_key_hex': signingPublicKeyHex,
        'encryption_public_key_pem': encryptionPublicKeyPem,
        'is_verified': isVerified,
        'previous_key_hex': previousKeyHex,
        'has_key_changed': hasKeyChanged,
      };

  factory Contact.fromJson(Map<String, dynamic> json) => Contact(
        userId: json['user_id'] as String,
        displayName: json['display_name'] as String,
        signingPublicKeyHex: json['signing_public_key_hex'] as String,
        encryptionPublicKeyPem: json['encryption_public_key_pem'] as String,
        isVerified: json['is_verified'] as bool? ?? false,
        previousKeyHex: json['previous_key_hex'] as String?,
        hasKeyChanged: json['has_key_changed'] as bool? ?? false,
      );
}

class ContactQrPayload {
  final String userId;
  final String displayName;
  final String signingPublicKeyHex;
  final String encryptionPublicKeyPem;

  ContactQrPayload({
    required this.userId,
    required this.displayName,
    required this.signingPublicKeyHex,
    required this.encryptionPublicKeyPem,
  });

  Map<String, dynamic> toJson() => {
        'type': 'contact_card',
        'user_id': userId,
        'display_name': displayName,
        'signing_pub': signingPublicKeyHex,
        'encryption_pub': encryptionPublicKeyPem,
      };

  String toJsonString() => json.encode(toJson());

  factory ContactQrPayload.fromJsonString(String jsonStr) {
    final map = json.decode(jsonStr) as Map<String, dynamic>;
    if (map['type'] != 'contact_card') {
      throw FormatException('Invalid QR code: expected type contact_card');
    }
    return ContactQrPayload(
      userId: map['user_id'] as String,
      displayName: map['display_name'] as String,
      signingPublicKeyHex: map['signing_pub'] as String,
      encryptionPublicKeyPem: map['encryption_pub'] as String,
    );
  }
}

/// Manages address book contacts, safety numbers, and key change alerts.
class ContactManager {
  final File? file;
  final Map<String, Contact> _contacts = {};

  ContactManager({this.file});

  Uint8List _hexToBytes(String hex) {
    final result = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < result.length; i++) {
      result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return result;
  }

  /// Loads contacts from disk.
  Future<void> load() async {
    final f = file;
    if (f == null || !await f.exists()) return;
    _contacts.clear();
    try {
      final content = await f.readAsString();
      if (content.trim().isEmpty) return;
      final list = json.decode(content) as List<dynamic>;
      for (final item in list) {
        final contact = Contact.fromJson(Map<String, dynamic>.from(item as Map));
        _contacts[contact.userId] = contact;
      }
    } catch (_) {}
  }

  /// Saves contacts to disk.
  Future<void> _save() async {
    final f = file;
    if (f == null) return;
    if (!await f.parent.exists()) {
      await f.parent.create(recursive: true);
    }
    final list = _contacts.values.map((c) => c.toJson()).toList();
    await f.writeAsString(json.encode(list));
  }

  /// Retrieves all contacts.
  List<Contact> getAllContacts() => _contacts.values.toList();

  /// Retrieves a specific contact by user ID.
  Contact? getContact(String userId) => _contacts[userId];

  /// Adds a contact from a scanned QR payload, or updates an existing contact.
  ///
  /// Detects if an existing contact's public key has changed (MITM or reinstallation).
  Future<Contact> addOrUpdateFromQr(ContactQrPayload payload) async {
    final existing = _contacts[payload.userId];

    if (existing != null) {
      if (existing.signingPublicKeyHex != payload.signingPublicKeyHex) {
        // SECURITY ALERT: Public key changed! Revoke verification and set alert flag.
        existing.previousKeyHex = existing.signingPublicKeyHex;
        existing.hasKeyChanged = true;
        existing.isVerified = false;
        // Update to the new key
        _contacts[payload.userId] = Contact(
          userId: payload.userId,
          displayName: payload.displayName,
          signingPublicKeyHex: payload.signingPublicKeyHex,
          encryptionPublicKeyPem: payload.encryptionPublicKeyPem,
          isVerified: false,
          previousKeyHex: existing.previousKeyHex,
          hasKeyChanged: true,
        );
        await _save();
        return _contacts[payload.userId]!;
      } else {
        // Unchanged key: update display name if changed
        final updated = Contact(
          userId: existing.userId,
          displayName: payload.displayName,
          signingPublicKeyHex: existing.signingPublicKeyHex,
          encryptionPublicKeyPem: payload.encryptionPublicKeyPem,
          isVerified: existing.isVerified,
          previousKeyHex: existing.previousKeyHex,
          hasKeyChanged: existing.hasKeyChanged,
        );
        _contacts[payload.userId] = updated;
        await _save();
        return updated;
      }
    } else {
      // New contact
      final newContact = Contact(
        userId: payload.userId,
        displayName: payload.displayName,
        signingPublicKeyHex: payload.signingPublicKeyHex,
        encryptionPublicKeyPem: payload.encryptionPublicKeyPem,
        isVerified: false,
        hasKeyChanged: false,
      );
      _contacts[payload.userId] = newContact;
      await _save();
      return newContact;
    }
  }

  /// Marks a contact as verified (e.g. after comparing safety numbers in person).
  Future<void> setVerified(String userId, bool verified) async {
    final contact = _contacts[userId];
    if (contact == null) {
      throw StateError('Contact $userId not found');
    }
    contact.isVerified = verified;
    if (verified) {
      contact.hasKeyChanged = false; // Acknowledged new key
    }
    await _save();
  }

  /// Computes the 60-digit symmetric safety number between local user and contact.
  String computeSafetyNumber(String userId, Uint8List localSigningKeyBytes) {
    final contact = _contacts[userId];
    if (contact == null) {
      throw StateError('Contact $userId not found');
    }

    final contactKeyBytes = _hexToBytes(contact.signingPublicKeyHex);
    return SafetyNumber.compute(localSigningKeyBytes, contactKeyBytes);
  }
}
