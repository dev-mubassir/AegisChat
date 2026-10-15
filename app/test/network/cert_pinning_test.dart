import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:app/network/cert_pinning.dart';
import 'package:flutter_test/flutter_test.dart';

class MockX509Certificate implements X509Certificate {
  @override
  final Uint8List der;

  MockX509Certificate(this.der);

  @override
  DateTime get endValidity => DateTime.now().add(const Duration(days: 365));

  @override
  String get issuer => 'CN=Test Issuer';

  @override
  Uint8List get sha1 => Uint8List(20);

  @override
  DateTime get startValidity => DateTime.now().subtract(const Duration(days: 1));

  @override
  String get subject => 'CN=securechat.test';

  @override
  String get pem => '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----';
}

void main() {
  group('Certificate Pinning Unit Tests', () {
    const primaryPin = 'sha256/k24z5f007W/pD8N2gR1oX6Z9v9m3qF0uV1z6Y4q8c7A=';
    const backupPin = 'sha256/m93v1x884K/qL1M5bR8pY2X7v6m1qF9uV4z2Y7q1c9B=';
    const wrongPin = 'sha256/0000000000000000000000000000000000000000000=';

    const testConfig = PinningConfig(
      primaryPin: primaryPin,
      backupPin: backupPin,
    );

    final pinner = CertificatePinner(config: testConfig);

    test('matchesRawPin succeeds for primary pin', () {
      expect(pinner.matchesRawPin(primaryPin), isTrue);
    });

    test('matchesRawPin succeeds for backup pin', () {
      expect(pinner.matchesRawPin(backupPin), isTrue);
    });

    test('matchesRawPin rejects wrong pin', () {
      expect(pinner.matchesRawPin(wrongPin), isFalse);
      expect(pinner.matchesRawPin(''), isFalse);
      expect(pinner.matchesRawPin('sha256/invalid_length'), isFalse);
    });

    test('matchesPin computes SHA-256 and validates DER certificate bytes', () {
      final certBytes1 = utf8.encode('CERTIFICATE_DER_SAMPLE_ONE_PRIMARY');
      final certBytes2 = utf8.encode('CERTIFICATE_DER_SAMPLE_TWO_BACKUP');
      final wrongCertBytes = utf8.encode('MALICIOUS_CERTIFICATE_DER_ATTACK');

      final pin1 = CertificatePinner.computePin(certBytes1);
      final pin2 = CertificatePinner.computePin(certBytes2);
      final wrongPinComputed = CertificatePinner.computePin(wrongCertBytes);

      expect(pin1, isNot(equals(pin2)));
      expect(pin1.startsWith('sha256/'), isTrue);

      final customPinner = CertificatePinner(
        config: PinningConfig(primaryPin: pin1, backupPin: pin2),
      );

      // Primary certificate matches
      expect(customPinner.matchesPin(certBytes1), isTrue);
      // Backup certificate matches
      expect(customPinner.matchesPin(certBytes2), isTrue);
      // Wrong certificate is rejected
      expect(customPinner.matchesPin(wrongCertBytes), isFalse);
      expect(customPinner.matchesRawPin(wrongPinComputed), isFalse);
    });

    test('badCertificateCallback validates X509Certificate', () {
      final certBytes = utf8.encode('MY_SERVER_CERTIFICATE_DATA');
      final expectedPin = CertificatePinner.computePin(certBytes);

      final pinnerWithCert = CertificatePinner(
        config: PinningConfig(primaryPin: expectedPin, backupPin: backupPin),
      );

      final validCert = MockX509Certificate(Uint8List.fromList(certBytes));
      final invalidCert = MockX509Certificate(Uint8List.fromList(utf8.encode('ATTACKER_DATA')));

      expect(pinnerWithCert.badCertificateCallback(validCert, 'example.com', 443), isTrue);
      expect(pinnerWithCert.badCertificateCallback(invalidCert, 'example.com', 443), isFalse);
    });
  });
}
