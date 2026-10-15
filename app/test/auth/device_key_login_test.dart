import 'dart:convert';
import 'dart:typed_data';

import 'package:app/auth/device_key.dart';
import 'package:app/auth/login_client.dart';
import 'package:app/crypto/keystore.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  group('SoftwareDeviceKey', () {
    test('generates valid SPKI PEM and creates verifiable ECDSA signatures', () async {
      final key = SoftwareDeviceKey.generate();
      expect(key.keyType, equals('software'));

      final pem = await key.getPublicKeyPem();
      expect(pem, startsWith('-----BEGIN PUBLIC KEY-----\n'));
      expect(pem, endsWith('-----END PUBLIC KEY-----\n'));

      final data = Uint8List.fromList(utf8.encode('test_challenge_nonce_abc123'));
      final signatureB64 = await key.sign(data);
      expect(signatureB64.isNotEmpty, isTrue);

      final sigBytes = base64.decode(signatureB64);
      expect(sigBytes[0], equals(0x30)); // ASN.1 SEQUENCE header for DER
    });
  });

  group('LoginClient', () {
    late InMemoryKeyStore keyStore;
    late SoftwareDeviceKey deviceKey;

    setUp(() {
      keyStore = InMemoryKeyStore();
      deviceKey = SoftwareDeviceKey.generate();
    });

    test('successful challenge-response login stores tokens and IDs', () async {
      final mockClient = MockClient((request) async {
        if (request.url.path == '/auth/challenge') {
          final body = json.decode(request.body) as Map<String, dynamic>;
          expect(body['user_id'], equals('alice'));
          expect(body['device_id'], equals('dev-01'));
          return http.Response(
            json.encode({
              'nonce': 'test_random_challenge_nonce_789',
              'expires_in': 60,
              'expires_at': 1770000060,
            }),
            200,
            headers: {'content-type': 'application/json'},
          );
        } else if (request.url.path == '/auth/verify') {
          final body = json.decode(request.body) as Map<String, dynamic>;
          expect(body['user_id'], equals('alice'));
          expect(body['device_id'], equals('dev-01'));
          expect(body['nonce'], equals('test_random_challenge_nonce_789'));
          expect(body['signature'], isNotEmpty);

          return http.Response(
            json.encode({
              'access_token': 'jwt_access_token_mock_111',
              'refresh_token': 'refresh_token_mock_222',
              'token_type': 'bearer',
              'expires_in': 600,
            }),
            200,
            headers: {'content-type': 'application/json'},
          );
        }
        return http.Response('Not Found', 404);
      });

      final client = LoginClient(
        baseUrl: 'http://localhost:8000',
        keyStore: keyStore,
        deviceKey: deviceKey,
        httpClient: mockClient,
      );

      final tokens = await client.login(userId: 'alice', deviceId: 'dev-01');
      expect(tokens.accessToken, equals('jwt_access_token_mock_111'));
      expect(tokens.refreshToken, equals('refresh_token_mock_222'));

      expect(await keyStore.read(LoginClient.keyAccessToken), equals('jwt_access_token_mock_111'));
      expect(await keyStore.read(LoginClient.keyRefreshToken), equals('refresh_token_mock_222'));
      expect(await keyStore.read(LoginClient.keyUserId), equals('alice'));
      expect(await keyStore.read(LoginClient.keyDeviceId), equals('dev-01'));
    });

    test('login handles challenge failure (e.g. device not registered)', () async {
      final mockClient = MockClient((request) async {
        return http.Response(
          json.encode({'detail': 'Device not registered'}),
          404,
          headers: {'content-type': 'application/json'},
        );
      });

      final client = LoginClient(
        baseUrl: 'http://localhost:8000',
        keyStore: keyStore,
        deviceKey: deviceKey,
        httpClient: mockClient,
      );

      await expectLater(
        client.login(userId: 'alice', deviceId: 'unknown_dev'),
        throwsA(isA<AuthException>().having((e) => e.statusCode, 'statusCode', equals(404))),
      );
    });

    test('login handles verification failure (e.g. invalid signature or expired challenge)', () async {
      final mockClient = MockClient((request) async {
        if (request.url.path == '/auth/challenge') {
          return http.Response(
            json.encode({
              'nonce': 'nonce_123',
              'expires_in': 60,
              'expires_at': 1770000060,
            }),
            200,
            headers: {'content-type': 'application/json'},
          );
        } else {
          return http.Response(
            json.encode({'detail': 'Invalid cryptographic signature'}),
            401,
            headers: {'content-type': 'application/json'},
          );
        }
      });

      final client = LoginClient(
        baseUrl: 'http://localhost:8000',
        keyStore: keyStore,
        deviceKey: deviceKey,
        httpClient: mockClient,
      );

      await expectLater(
        client.login(userId: 'alice', deviceId: 'dev-01'),
        throwsA(isA<AuthException>().having((e) => e.statusCode, 'statusCode', equals(401))),
      );
    });

    test('refreshToken successfully rotates token and writes to KeyStore', () async {
      await keyStore.write(LoginClient.keyRefreshToken, 'old_refresh_token_val');

      final mockClient = MockClient((request) async {
        expect(request.url.path, equals('/auth/refresh'));
        final body = json.decode(request.body) as Map<String, dynamic>;
        expect(body['refresh_token'], equals('old_refresh_token_val'));

        return http.Response(
          json.encode({
            'access_token': 'new_jwt_access_333',
            'refresh_token': 'new_refresh_token_444',
            'token_type': 'bearer',
            'expires_in': 600,
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final client = LoginClient(
        baseUrl: 'http://localhost:8000',
        keyStore: keyStore,
        deviceKey: deviceKey,
        httpClient: mockClient,
      );

      final rotated = await client.refreshToken();
      expect(rotated.accessToken, equals('new_jwt_access_333'));
      expect(rotated.refreshToken, equals('new_refresh_token_444'));

      expect(await keyStore.read(LoginClient.keyAccessToken), equals('new_jwt_access_333'));
      expect(await keyStore.read(LoginClient.keyRefreshToken), equals('new_refresh_token_444'));
    });

    test('refreshToken clears tokens upon reuse detection or failure', () async {
      await keyStore.write(LoginClient.keyAccessToken, 'old_access');
      await keyStore.write(LoginClient.keyRefreshToken, 'reused_refresh_token');

      final mockClient = MockClient((request) async {
        return http.Response(
          json.encode({'detail': 'Refresh token reuse detected. Token family revoked.'}),
          401,
          headers: {'content-type': 'application/json'},
        );
      });

      final client = LoginClient(
        baseUrl: 'http://localhost:8000',
        keyStore: keyStore,
        deviceKey: deviceKey,
        httpClient: mockClient,
      );

      await expectLater(
        client.refreshToken(),
        throwsA(isA<AuthException>().having((e) => e.statusCode, 'statusCode', equals(401))),
      );

      // Verify tokens were cleared for security
      expect(await keyStore.read(LoginClient.keyAccessToken), isNull);
      expect(await keyStore.read(LoginClient.keyRefreshToken), isNull);
    });

    test('logout clears access and refresh tokens', () async {
      await keyStore.write(LoginClient.keyAccessToken, 'token_a');
      await keyStore.write(LoginClient.keyRefreshToken, 'token_b');

      final client = LoginClient(
        baseUrl: 'http://localhost:8000',
        keyStore: keyStore,
        deviceKey: deviceKey,
      );

      await client.logout();
      expect(await keyStore.read(LoginClient.keyAccessToken), isNull);
      expect(await keyStore.read(LoginClient.keyRefreshToken), isNull);
    });
  });
}
