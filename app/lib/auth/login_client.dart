import 'dart:convert';
import 'dart:typed_data';

import 'package:app/auth/device_key.dart';
import 'package:app/crypto/keystore.dart';
import 'package:http/http.dart' as http;

class AuthException implements Exception {
  final String message;
  final int? statusCode;

  AuthException(this.message, [this.statusCode]);

  @override
  String toString() => 'AuthException: $message (status: $statusCode)';
}

class AuthTokens {
  final String accessToken;
  final String refreshToken;
  final int expiresIn;
  final String tokenType;

  AuthTokens({
    required this.accessToken,
    required this.refreshToken,
    required this.expiresIn,
    this.tokenType = 'bearer',
  });
}

/// Client for challenge-response authentication, token storage, and refresh rotation.
class LoginClient {
  final String baseUrl;
  final http.Client _httpClient;
  final KeyStore _keyStore;
  final DeviceKey _deviceKey;

  static const String keyAccessToken = 'auth_access_token';
  static const String keyRefreshToken = 'auth_refresh_token';
  static const String keyUserId = 'auth_user_id';
  static const String keyDeviceId = 'auth_device_id';

  LoginClient({
    required this.baseUrl,
    required this._keyStore,
    required this._deviceKey,
    http.Client? httpClient,
  })  : _httpClient = httpClient ?? http.Client();

  /// Performs challenge-response cryptographic login and securely stores tokens.
  Future<AuthTokens> login({
    required String userId,
    required String deviceId,
  }) async {
    // 1. Request challenge nonce
    final challengeUri = Uri.parse('$baseUrl/auth/challenge');
    final challengeRes = await _httpClient.post(
      challengeUri,
      headers: {'content-type': 'application/json'},
      body: json.encode({'user_id': userId, 'device_id': deviceId}),
    );

    if (challengeRes.statusCode != 200) {
      throw AuthException(
        'Challenge request failed: ${challengeRes.body}',
        challengeRes.statusCode,
      );
    }

    final challengeData = json.decode(challengeRes.body) as Map<String, dynamic>;
    final nonce = challengeData['nonce'] as String;

    // 2. Sign challenge nonce using device key
    final nonceBytes = Uint8List.fromList(utf8.encode(nonce));
    final signature = await _deviceKey.sign(nonceBytes);

    // 3. Verify signature and obtain JWT access + rotating refresh token
    final verifyUri = Uri.parse('$baseUrl/auth/verify');
    final verifyRes = await _httpClient.post(
      verifyUri,
      headers: {'content-type': 'application/json'},
      body: json.encode({
        'user_id': userId,
        'device_id': deviceId,
        'nonce': nonce,
        'signature': signature,
      }),
    );

    if (verifyRes.statusCode != 200) {
      throw AuthException(
        'Authentication verification failed: ${verifyRes.body}',
        verifyRes.statusCode,
      );
    }

    final verifyData = json.decode(verifyRes.body) as Map<String, dynamic>;
    final tokens = AuthTokens(
      accessToken: verifyData['access_token'] as String,
      refreshToken: verifyData['refresh_token'] as String,
      expiresIn: verifyData['expires_in'] as int? ?? 600,
      tokenType: verifyData['token_type'] as String? ?? 'bearer',
    );

    // 4. Securely store credentials in KeyStore
    await _keyStore.write(keyAccessToken, tokens.accessToken);
    await _keyStore.write(keyRefreshToken, tokens.refreshToken);
    await _keyStore.write(keyUserId, userId);
    await _keyStore.write(keyDeviceId, deviceId);

    return tokens;
  }

  /// Rotates the refresh token and stores the new access and refresh tokens.
  Future<AuthTokens> refreshToken() async {
    final currentRefreshToken = await _keyStore.read(keyRefreshToken);
    if (currentRefreshToken == null || currentRefreshToken.isEmpty) {
      throw AuthException('No refresh token available to rotate', 401);
    }

    final refreshUri = Uri.parse('$baseUrl/auth/refresh');
    final refreshRes = await _httpClient.post(
      refreshUri,
      headers: {'content-type': 'application/json'},
      body: json.encode({'refresh_token': currentRefreshToken}),
    );

    if (refreshRes.statusCode != 200) {
      // If refresh fails (reuse or revoked), clear stored tokens to force re-login
      await logout();
      throw AuthException(
        'Refresh token rotation failed: ${refreshRes.body}',
        refreshRes.statusCode,
      );
    }

    final refreshData = json.decode(refreshRes.body) as Map<String, dynamic>;
    final tokens = AuthTokens(
      accessToken: refreshData['access_token'] as String,
      refreshToken: refreshData['refresh_token'] as String,
      expiresIn: refreshData['expires_in'] as int? ?? 600,
      tokenType: refreshData['token_type'] as String? ?? 'bearer',
    );

    await _keyStore.write(keyAccessToken, tokens.accessToken);
    await _keyStore.write(keyRefreshToken, tokens.refreshToken);

    return tokens;
  }

  /// Clears stored authentication tokens from secure storage.
  Future<void> logout() async {
    await _keyStore.delete(keyAccessToken);
    await _keyStore.delete(keyRefreshToken);
  }

  /// Retrieves the current access token, or null if unauthenticated.
  Future<String?> getAccessToken() => _keyStore.read(keyAccessToken);

  /// Retrieves the stored user ID.
  Future<String?> getUserId() => _keyStore.read(keyUserId);

  /// Retrieves the stored device ID.
  Future<String?> getDeviceId() => _keyStore.read(keyDeviceId);
}
