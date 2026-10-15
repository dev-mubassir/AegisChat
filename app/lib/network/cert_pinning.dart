import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Central configuration for TLS Certificate Pinning.
///
/// Contains the active SHA-256 public key / certificate hash and one pre-generated backup pin.
class PinningConfig {
  /// Primary SHA-256 pin (base64 encoded).
  final String primaryPin;

  /// Backup SHA-256 pin for seamless key rotation without breaking client access.
  final String backupPin;

  const PinningConfig({
    required this.primaryPin,
    required this.backupPin,
  });

  /// Default production pinning configuration for SecureChat.
  /// Replace with your production domain's actual SHA-256 pins.
  static const PinningConfig defaultConfig = PinningConfig(
    primaryPin: 'sha256/k24z5f007W/pD8N2gR1oX6Z9v9m3qF0uV1z6Y4q8c7A=',
    backupPin: 'sha256/m93v1x884K/qL1M5bR8pY2X7v6m1qF9uV4z2Y7q1c9B=',
  );

  List<String> get allowedPins => [primaryPin, backupPin];
}

/// Evaluates server TLS certificates against primary and backup SHA-256 pins.
class CertificatePinner {
  final PinningConfig config;

  const CertificatePinner({this.config = PinningConfig.defaultConfig});

  /// Computes the standard SHA-256 pin string from raw DER certificate bytes.
  static String computePin(List<int> derBytes) {
    final digest = SHA256Digest().process(Uint8List.fromList(derBytes));
    return 'sha256/${base64.encode(digest)}';
  }

  /// Evaluates whether the certificate's DER bytes match either the primary or backup pin.
  bool matchesPin(List<int> derBytes) {
    final computed = computePin(derBytes);
    return matchesRawPin(computed);
  }

  /// Checks a pre-computed pin string against allowed primary and backup pins using constant-time comparison.
  bool matchesRawPin(String candidatePin) {
    for (final allowed in config.allowedPins) {
      if (_constantTimeEquals(candidatePin, allowed)) {
        return true;
      }
    }
    return false;
  }

  /// Constant-time string comparison to prevent timing attacks.
  static bool _constantTimeEquals(String a, String b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }
    return result == 0;
  }

  /// Validates an X509 certificate during TLS handshake.
  bool badCertificateCallback(X509Certificate cert, String host, int port) {
    return matchesPin(cert.der);
  }

  /// Configures and returns an [HttpClient] enforcing certificate pinning.
  HttpClient createPinnedClient({SecurityContext? context}) {
    final client = HttpClient(context: context);
    client.badCertificateCallback = badCertificateCallback;
    return client;
  }
}
