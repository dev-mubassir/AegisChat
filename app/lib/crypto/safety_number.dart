import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Computes symmetric 60-digit safety numbers and QR verification payloads for public keys.
class SafetyNumber {
  /// Compares two byte lists lexicographically to ensure canonical ordering.
  static int _compareByteLists(Uint8List a, Uint8List b) {
    final len = a.length < b.length ? a.length : b.length;
    for (var i = 0; i < len; i++) {
      if (a[i] != b[i]) {
        return a[i].compareTo(b[i]);
      }
    }
    return a.length.compareTo(b.length);
  }

  /// Sorts two public keys canonically so both endpoints compute the identical fingerprint.
  static List<Uint8List> _sortKeys(Uint8List keyA, Uint8List keyB) {
    if (_compareByteLists(keyA, keyB) <= 0) {
      return [keyA, keyB];
    } else {
      return [keyB, keyA];
    }
  }

  /// Computes a 60-digit safety number (formatted as 12 groups of 5 digits) from two public keys.
  static String compute(Uint8List keyA, Uint8List keyB) {
    final sorted = _sortKeys(keyA, keyB);

    // Iterative SHA-512 hashing for key derivation
    final sha512 = SHA512Digest();
    final input = Uint8List.fromList([...sorted[0], ...sorted[1]]);
    var hash = sha512.process(input);

    // Run 5 iterations to stretch input
    for (var i = 0; i < 5; i++) {
      hash = sha512.process(hash);
    }

    // Extract 12 chunks of 4 bytes -> 12 five-digit numbers
    final groups = <String>[];
    final byteData = ByteData.sublistView(hash);

    for (var i = 0; i < 12; i++) {
      final value = byteData.getUint32(i * 4, Endian.big);
      final digits = (value % 100000).toString().padLeft(5, '0');
      groups.add(digits);
    }

    return groups.join(' ');
  }

  /// Generates a standardized QR code JSON payload from two public keys.
  static String generateQrPayload(Uint8List keyA, Uint8List keyB) {
    final sorted = _sortKeys(keyA, keyB);
    final fingerprint = compute(keyA, keyB);

    final payload = {
      'v': 1,
      'fingerprint': fingerprint,
      'keys': [
        base64.encode(sorted[0]),
        base64.encode(sorted[1]),
      ],
    };

    return json.encode(payload);
  }

  /// Verifies a scanned QR payload against the local and remote public keys.
  static bool verifyQrPayload({
    required String qrPayload,
    required Uint8List localKey,
    required Uint8List remoteKey,
  }) {
    try {
      final decoded = json.decode(qrPayload) as Map<String, dynamic>;
      if (decoded['v'] != 1) return false;

      final expectedFingerprint = compute(localKey, remoteKey);
      final actualFingerprint = decoded['fingerprint'] as String;

      return expectedFingerprint == actualFingerprint;
    } catch (_) {
      return false;
    }
  }
}
