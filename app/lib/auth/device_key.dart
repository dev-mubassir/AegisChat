import 'dart:convert';
import 'dart:math';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:pointycastle/export.dart';

/// Abstract interface for device identity keys used in cryptographic challenge-response login.
abstract class DeviceKey {
  /// Returns the SubjectPublicKeyInfo (SPKI) PEM string for the public key.
  Future<String> getPublicKeyPem();

  /// Signs [data] using ECDSA P-256 with SHA-256, returning base64 DER signature.
  Future<String> sign(Uint8List data);

  /// Hardware or software key type identifier.
  String get keyType;
}

/// Hardware-backed device key interface for Android Keystore (StrongBox) and iOS Secure Enclave.
///
/// Keys are generated inside secure hardware, non-exportable, and biometric-gated.
/// Communication is performed across a Flutter platform channel.
class HardwareDeviceKey implements DeviceKey {
  static const MethodChannel _channel = MethodChannel('com.securechat.app/device_key');

  const HardwareDeviceKey();

  @override
  String get keyType => 'hardware';

  @override
  Future<String> getPublicKeyPem() async {
    final result = await _channel.invokeMethod<String>('getPublicKeyPem');
    if (result == null || result.isEmpty) {
      throw StateError('Failed to retrieve hardware public key PEM from platform channel');
    }
    return result;
  }

  @override
  Future<String> sign(Uint8List data) async {
    final result = await _channel.invokeMethod<String>('sign', {'data': data});
    if (result == null || result.isEmpty) {
      throw StateError('Failed to sign challenge with hardware device key');
    }
    return result;
  }
}

/// Software-implemented ECDSA P-256 device key strictly for unit and integration testing.
///
/// SECURITY RULE: This key is NEVER permitted to be used in production or release builds.
class SoftwareDeviceKey implements DeviceKey {
  final ECPublicKey publicKey;
  final ECPrivateKey _privateKey;
  final SecureRandom _secureRandom;

  SoftwareDeviceKey._({
    required this.publicKey,
    required this._privateKey,
    required this._secureRandom,
  });

  /// Creates a software device key pair. Throws in release mode unless [allowInReleaseForTesting] is explicitly true.
  static SoftwareDeviceKey generate({bool allowInReleaseForTesting = false}) {
    if (kReleaseMode && !allowInReleaseForTesting) {
      throw UnsupportedError(
        'SoftwareDeviceKey is strictly forbidden in release builds! Hardware-backed keys are required.',
      );
    }

    final domain = ECDomainParameters('prime256v1');
    final keyGen = ECKeyGenerator();
    final secureRandom = FortunaRandom();
    final rand = Random.secure();
    final seed = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      seed[i] = rand.nextInt(256);
    }
    secureRandom.seed(KeyParameter(seed));

    keyGen.init(ParametersWithRandom(ECKeyGeneratorParameters(domain), secureRandom));
    final pair = keyGen.generateKeyPair();

    return SoftwareDeviceKey._(
      publicKey: pair.publicKey,
      privateKey: pair.privateKey,
      secureRandom: secureRandom,
    );
  }

  @override
  String get keyType => 'software';

  static Uint8List _bigIntToBytes(BigInt n) {
    var hex = n.toRadixString(16);
    if (hex.length % 2 != 0) hex = '0$hex';
    final result = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < result.length; i++) {
      result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return result;
  }

  static Uint8List _encodeDerInteger(BigInt n) {
    var bytes = _bigIntToBytes(n);
    if (bytes.isNotEmpty && (bytes[0] & 0x80) != 0) {
      bytes = Uint8List.fromList([0x00, ...bytes]);
    }
    return Uint8List.fromList([0x02, bytes.length, ...bytes]);
  }

  static Uint8List _encodeDsaSignature(BigInt r, BigInt s) {
    final rBytes = _encodeDerInteger(r);
    final sBytes = _encodeDerInteger(s);
    final len = rBytes.length + sBytes.length;
    return Uint8List.fromList([0x30, len, ...rBytes, ...sBytes]);
  }

  static Uint8List _pad32(Uint8List bytes) {
    if (bytes.length >= 32) return bytes.sublist(bytes.length - 32);
    final res = Uint8List(32);
    res.setRange(32 - bytes.length, 32, bytes);
    return res;
  }

  @override
  Future<String> getPublicKeyPem() async {
    // SubjectPublicKeyInfo (SPKI) for P-256 (prime256v1)
    final header = [
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
      0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
      0x42, 0x00,
    ];
    final xBytes = _pad32(_bigIntToBytes(publicKey.Q!.x!.toBigInteger()!));
    final yBytes = _pad32(_bigIntToBytes(publicKey.Q!.y!.toBigInteger()!));
    final uncompressed = [0x04, ...xBytes, ...yBytes];
    final spki = Uint8List.fromList([...header, ...uncompressed]);
    final b64 = base64.encode(spki);
    return '-----BEGIN PUBLIC KEY-----\n$b64\n-----END PUBLIC KEY-----\n';
  }

  @override
  Future<String> sign(Uint8List data) async {
    final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64));
    signer.init(
      true,
      ParametersWithRandom(PrivateKeyParameter<ECPrivateKey>(_privateKey), _secureRandom),
    );
    final sig = signer.generateSignature(data) as ECSignature;
    final derSig = _encodeDsaSignature(sig.r, sig.s);
    return base64.encode(derSig);
  }
}
