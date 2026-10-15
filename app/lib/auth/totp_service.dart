import 'dart:convert';
import 'dart:typed_data';

import 'package:app/auth/device_key.dart';
import 'package:http/http.dart' as http;

class TotpException implements Exception {
  final String message;
  final int? statusCode;
  TotpException(this.message, [this.statusCode]);
  @override
  String toString() => 'TotpException: $message (status: $statusCode)';
}

class TotpEnrollmentData {
  final String secret;
  final String otpauthUrl;
  final List<String> recoveryCodes;

  TotpEnrollmentData({
    required this.secret,
    required this.otpauthUrl,
    required this.recoveryCodes,
  });

  factory TotpEnrollmentData.fromJson(Map<String, dynamic> json) {
    return TotpEnrollmentData(
      secret: json['secret'] as String,
      otpauthUrl: json['otpauth_url'] as String,
      recoveryCodes: (json['recovery_codes'] as List<dynamic>).map((e) => e.toString()).toList(),
    );
  }
}

class DeviceApprovalPayload {
  final String userId;
  final String newDeviceId;
  final String newDeviceSigningPub;
  final String newDeviceEncryptionPub;

  DeviceApprovalPayload({
    required this.userId,
    required this.newDeviceId,
    required this.newDeviceSigningPub,
    required this.newDeviceEncryptionPub,
  });

  Map<String, dynamic> toJson() => {
        'type': 'device_approval_request',
        'user_id': userId,
        'new_device_id': newDeviceId,
        'new_device_signing_pub': newDeviceSigningPub,
        'new_device_encryption_pub': newDeviceEncryptionPub,
      };

  String toJsonString() => json.encode(toJson());

  factory DeviceApprovalPayload.fromJsonString(String jsonString) {
    final map = json.decode(jsonString) as Map<String, dynamic>;
    return DeviceApprovalPayload(
      userId: map['user_id'] as String,
      newDeviceId: map['new_device_id'] as String,
      newDeviceSigningPub: map['new_device_signing_pub'] as String,
      newDeviceEncryptionPub: map['new_device_encryption_pub'] as String,
    );
  }

  /// Builds the canonical UTF-8 bytes matching server's Python json.dumps(..., sort_keys=True).
  Uint8List toCanonicalBytes() {
    final canonicalStr =
        '{"new_device_encryption_pub": ${json.encode(newDeviceEncryptionPub)}, '
        '"new_device_id": ${json.encode(newDeviceId)}, '
        '"new_device_signing_pub": ${json.encode(newDeviceSigningPub)}, '
        '"user_id": ${json.encode(userId)}}';
    return Uint8List.fromList(utf8.encode(canonicalStr));
  }
}

class TotpService {
  final String baseUrl;
  final http.Client _httpClient;

  TotpService({required this.baseUrl, http.Client? httpClient})
      : _httpClient = httpClient ?? http.Client();

  /// Requests a fresh TOTP enrollment secret and 10 single-use recovery codes.
  Future<TotpEnrollmentData> enrollTotp({required String accessToken}) async {
    final uri = Uri.parse('$baseUrl/auth/totp/enroll');
    final res = await _httpClient.post(
      uri,
      headers: {
        'authorization': 'Bearer $accessToken',
        'content-type': 'application/json',
      },
    );

    if (res.statusCode != 200) {
      throw TotpException('TOTP enrollment failed: ${res.body}', res.statusCode);
    }

    final data = json.decode(res.body) as Map<String, dynamic>;
    return TotpEnrollmentData.fromJson(data);
  }

  /// Verifies a 6-digit TOTP code to confirm activation on the server.
  Future<void> confirmTotp({required String accessToken, required String code}) async {
    final uri = Uri.parse('$baseUrl/auth/totp/confirm');
    final res = await _httpClient.post(
      uri,
      headers: {
        'authorization': 'Bearer $accessToken',
        'content-type': 'application/json',
      },
      body: json.encode({'code': code}),
    );

    if (res.statusCode != 200) {
      throw TotpException('TOTP confirmation failed: ${res.body}', res.statusCode);
    }
  }

  /// Old device approves a new device by signing the new device's keys and providing a TOTP code.
  Future<void> approveNewDevice({
    required String oldDeviceId,
    required DeviceApprovalPayload newDevice,
    required DeviceKey oldDeviceKey,
    required String totpCode,
  }) async {
    final canonicalBytes = newDevice.toCanonicalBytes();
    final approvalSignature = await oldDeviceKey.sign(canonicalBytes);

    final uri = Uri.parse('$baseUrl/devices/approve');
    final res = await _httpClient.post(
      uri,
      headers: {'content-type': 'application/json'},
      body: json.encode({
        'user_id': newDevice.userId,
        'old_device_id': oldDeviceId,
        'new_device_id': newDevice.newDeviceId,
        'new_device_signing_pub': newDevice.newDeviceSigningPub,
        'new_device_encryption_pub': newDevice.newDeviceEncryptionPub,
        'approval_signature': approvalSignature,
        'totp_code': totpCode,
      }),
    );

    if (res.statusCode != 200) {
      throw TotpException('Device approval failed: ${res.body}', res.statusCode);
    }
  }
}
