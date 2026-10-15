import 'dart:convert';

import 'package:app/auth/device_key.dart';
import 'package:app/auth/totp_service.dart';
import 'package:app/ui/device_approval_screen.dart';
import 'package:app/ui/totp_enrollment_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  group('TotpService & Canonical Payload', () {
    test('enrollTotp and confirmTotp work over HTTP', () async {
      final mockClient = MockClient((request) async {
        if (request.url.path == '/auth/totp/enroll') {
          expect(request.headers['authorization'], equals('Bearer test_access_token'));
          return http.Response(
            json.encode({
              'secret': 'JBSWY3DPEHPK3PXP',
              'otpauth_url': 'otpauth://totp/SecureChat:alice?secret=JBSWY3DPEHPK3PXP',
              'recovery_codes': [
                'code1',
                'code2',
                'code3',
                'code4',
                'code5',
                'code6',
                'code7',
                'code8',
                'code9',
                'code10',
              ],
            }),
            200,
            headers: {'content-type': 'application/json'},
          );
        } else if (request.url.path == '/auth/totp/confirm') {
          final body = json.decode(request.body) as Map<String, dynamic>;
          expect(body['code'], equals('123456'));
          return http.Response(json.encode({'status': 'ok'}), 200,
              headers: {'content-type': 'application/json'});
        }
        return http.Response('Not Found', 404);
      });

      final service = TotpService(baseUrl: 'http://localhost:8000', httpClient: mockClient);

      final enrollment = await service.enrollTotp(accessToken: 'test_access_token');
      expect(enrollment.secret, equals('JBSWY3DPEHPK3PXP'));
      expect(enrollment.recoveryCodes.length, equals(10));

      await service.confirmTotp(accessToken: 'test_access_token', code: '123456');
    });

    test('approveNewDevice signs canonical payload correctly', () async {
      final oldKey = SoftwareDeviceKey.generate();
      final newDevice = DeviceApprovalPayload(
        userId: 'alice',
        newDeviceId: 'dev-phone-2',
        newDeviceSigningPub: '-----BEGIN PUBLIC KEY-----\nSPKI2\n-----END PUBLIC KEY-----\n',
        newDeviceEncryptionPub: '-----BEGIN PUBLIC KEY-----\nRSA2\n-----END PUBLIC KEY-----\n',
      );

      final mockClient = MockClient((request) async {
        expect(request.url.path, equals('/devices/approve'));
        final body = json.decode(request.body) as Map<String, dynamic>;
        expect(body['user_id'], equals('alice'));
        expect(body['old_device_id'], equals('dev-phone-1'));
        expect(body['new_device_id'], equals('dev-phone-2'));
        expect(body['totp_code'], equals('654321'));
        expect(body['approval_signature'], isNotEmpty);

        return http.Response(json.encode({'status': 'ok', 'device_id': 'dev-phone-2'}), 200,
            headers: {'content-type': 'application/json'});
      });

      final service = TotpService(baseUrl: 'http://localhost:8000', httpClient: mockClient);

      await service.approveNewDevice(
        oldDeviceId: 'dev-phone-1',
        newDevice: newDevice,
        oldDeviceKey: oldKey,
        totpCode: '654321',
      );
    });
  });

  group('TOTP & Device Approval UI Widget Tests', () {
    testWidgets('TotpEnrollmentScreen renders QR and transitions to recovery codes',
        (tester) async {
      final mockClient = MockClient((request) async {
        if (request.url.path == '/auth/totp/enroll') {
          return http.Response(
            json.encode({
              'secret': 'TESTSECRET123',
              'otpauth_url': 'otpauth://totp/SecureChat:alice?secret=TESTSECRET123',
              'recovery_codes': List.generate(10, (i) => 'rec-code-$i'),
            }),
            200,
            headers: {'content-type': 'application/json'},
          );
        } else if (request.url.path == '/auth/totp/confirm') {
          return http.Response(json.encode({'status': 'ok'}), 200,
              headers: {'content-type': 'application/json'});
        }
        return http.Response('Not Found', 404);
      });

      final service = TotpService(baseUrl: 'http://localhost:8000', httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: TotpEnrollmentScreen(
            totpService: service,
            accessToken: 'dummy_token',
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('Scan QR Code with Authenticator App'), findsOneWidget);
      expect(find.textContaining('TESTSECRET123'), findsOneWidget);

      // Enter 6-digit code
      await tester.enterText(find.byKey(const Key('totp_code_input')), '123456');
      await tester.tap(find.byKey(const Key('confirm_totp_button')));
      await tester.pumpAndSettle();

      // Should now display recovery codes
      expect(find.text('Save Your Recovery Codes'), findsOneWidget);
      expect(find.text('rec-code-0'), findsOneWidget);
      expect(find.text('rec-code-9'), findsOneWidget);

      // Finish button should be disabled until checkbox checked
      final finishBtn = tester.widget<ElevatedButton>(find.byKey(const Key('finish_totp_button')));
      expect(finishBtn.onPressed, isNull);

      // Check the backup checkbox (scroll into view first)
      await tester.ensureVisible(find.byKey(const Key('backup_confirm_checkbox')));
      await tester.tap(find.byKey(const Key('backup_confirm_checkbox')));
      await tester.pumpAndSettle();

      await tester.ensureVisible(find.byKey(const Key('finish_totp_button')));
      final finishBtnEnabled =
          tester.widget<ElevatedButton>(find.byKey(const Key('finish_totp_button')));
      expect(finishBtnEnabled.onPressed, isNotNull);
    });

    testWidgets('DeviceApprovalScreen in new-device mode displays QR code', (tester) async {
      final service = TotpService(baseUrl: 'http://localhost:8000');
      final key = SoftwareDeviceKey.generate();
      final payload = DeviceApprovalPayload(
        userId: 'bob',
        newDeviceId: 'bob-tablet',
        newDeviceSigningPub: 'pub_key_1',
        newDeviceEncryptionPub: 'pub_key_2',
      );

      await tester.pumpWidget(
        MaterialApp(
          home: DeviceApprovalScreen(
            totpService: service,
            oldDeviceId: 'bob-phone',
            oldDeviceKey: key,
            newDevicePayload: payload,
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('Scan on Your Existing Device'), findsOneWidget);
      expect(find.text('Device ID: bob-tablet'), findsOneWidget);
    });

    testWidgets('DeviceApprovalScreen in approver mode approves valid payload', (tester) async {
      final key = SoftwareDeviceKey.generate();
      final mockClient = MockClient((request) async {
        return http.Response(json.encode({'status': 'ok'}), 200,
            headers: {'content-type': 'application/json'});
      });
      final service = TotpService(baseUrl: 'http://localhost:8000', httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: DeviceApprovalScreen(
            totpService: service,
            oldDeviceId: 'alice-phone',
            oldDeviceKey: key,
          ),
        ),
      );

      await tester.pumpAndSettle();

      final payload = DeviceApprovalPayload(
        userId: 'alice',
        newDeviceId: 'alice-ipad',
        newDeviceSigningPub: 'signing_pub_test',
        newDeviceEncryptionPub: 'encryption_pub_test',
      );

      // Paste payload JSON
      await tester.enterText(
        find.byKey(const Key('approval_payload_input')),
        payload.toJsonString(),
      );
      await tester.pumpAndSettle();

      expect(find.text('User: alice'), findsOneWidget);
      expect(find.text('New Device ID: alice-ipad'), findsOneWidget);

      // Enter TOTP code
      await tester.enterText(find.byKey(const Key('approval_totp_input')), '654321');
      await tester.tap(find.byKey(const Key('submit_approval_button')));
      await tester.pumpAndSettle();

      expect(find.textContaining('Device approved successfully!'), findsOneWidget);
    });
  });
}
