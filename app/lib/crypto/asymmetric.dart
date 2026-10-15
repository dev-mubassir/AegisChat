import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pointycastle/export.dart';

/// Container for an RSA-2048 keypair.
class RsaKeyPair {
  final RSAPublicKey publicKey;
  final RSAPrivateKey privateKey;

  RsaKeyPair({required this.publicKey, required this.privateKey});
}

/// DTO for passing serialized RSA BigInts across isolates if needed.
class _RsaRawData {
  final BigInt modulus;
  final BigInt publicExponent;
  final BigInt privateExponent;
  final BigInt p;
  final BigInt q;

  _RsaRawData({
    required this.modulus,
    required this.publicExponent,
    required this.privateExponent,
    required this.p,
    required this.q,
  });
}

_RsaRawData _generateRsaRawInIsolate() {
  final secureRandom = FortunaRandom();
  final rand = Random.secure();
  final seed = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    seed[i] = rand.nextInt(256);
  }
  secureRandom.seed(KeyParameter(seed));

  final rsaParams = RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64);
  final params = ParametersWithRandom(rsaParams, secureRandom);
  final generator = RSAKeyGenerator()..init(params);
  final pair = generator.generateKeyPair();

  final pub = pair.publicKey;
  final priv = pair.privateKey;

  return _RsaRawData(
    modulus: pub.modulus!,
    publicExponent: pub.exponent!,
    privateExponent: priv.exponent!,
    p: priv.p!,
    q: priv.q!,
  );
}

/// RSA-2048 OAEP-SHA256 key wrapping and unwrapping.
class RsaOaep {
  SecureRandom _getSecureRandom() {
    final secureRandom = FortunaRandom();
    final rand = Random.secure();
    final seed = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      seed[i] = rand.nextInt(256);
    }
    secureRandom.seed(KeyParameter(seed));
    return secureRandom;
  }

  /// Generates a fresh RSA-2048 keypair inside a background worker isolate.
  Future<RsaKeyPair> generateKeyPair() async {
    final raw = await Isolate.run(_generateRsaRawInIsolate);
    final pubKey = RSAPublicKey(raw.modulus, raw.publicExponent);
    final privKey = RSAPrivateKey(
      raw.modulus,
      raw.privateExponent,
      raw.p,
      raw.q,
    );
    return RsaKeyPair(publicKey: pubKey, privateKey: privKey);
  }

  /// Wraps (encrypts) a 32-byte AES key using RSA-2048 and OAEP-SHA256 with randomized padding.
  Uint8List wrapKey({
    required RSAPublicKey publicKey,
    required Uint8List aesKey,
  }) {
    if (aesKey.length != 32) {
      throw ArgumentError('RSA-OAEP key wrapping is for 32-byte AES keys only');
    }

    final cipher = OAEPEncoding.withCustomDigest(() => SHA256Digest(), RSAEngine());
    final params = ParametersWithRandom(
      PublicKeyParameter<RSAPublicKey>(publicKey),
      _getSecureRandom(),
    );
    cipher.init(true, params);
    return cipher.process(aesKey);
  }

  /// Unwraps (decrypts) a wrapped key using RSA-2048 and OAEP-SHA256.
  Uint8List unwrapKey({
    required RSAPrivateKey privateKey,
    required Uint8List wrappedKey,
  }) {
    if (wrappedKey.length != 256) {
      throw ArgumentError('Wrapped key must be 256 bytes (2048 bits)');
    }

    try {
      final cipher = OAEPEncoding.withCustomDigest(() => SHA256Digest(), RSAEngine());
      cipher.init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
      return cipher.process(wrappedKey);
    } catch (e) {
      throw ArgumentError('Failed to unwrap key: $e');
    }
  }
}

/// Ed25519 digital signature generation and verification.
class MessageSigner {
  final crypto.Ed25519 _algorithm = crypto.Ed25519();

  /// Generates an Ed25519 keypair for message signing.
  Future<crypto.SimpleKeyPair> generateKeyPair() async {
    return await _algorithm.newKeyPair();
  }

  /// Extracts the 32-byte public key representation.
  Future<Uint8List> getPublicKeyBytes(crypto.SimpleKeyPair keyPair) async {
    final pub = await keyPair.extractPublicKey();
    return Uint8List.fromList(pub.bytes);
  }

  /// Signs [message] with [keyPair], returning 64-byte Ed25519 signature.
  Future<Uint8List> sign({
    required crypto.SimpleKeyPair keyPair,
    required List<int> message,
  }) async {
    final sig = await _algorithm.sign(message, keyPair: keyPair);
    return Uint8List.fromList(sig.bytes);
  }

  /// Verifies that [signatureBytes] is valid for [message] under [publicKeyBytes].
  Future<bool> verify({
    required List<int> publicKeyBytes,
    required List<int> message,
    required List<int> signatureBytes,
  }) async {
    if (publicKeyBytes.length != 32 || signatureBytes.length != 64) {
      return false;
    }

    final pubKey = crypto.SimplePublicKey(
      publicKeyBytes,
      type: crypto.KeyPairType.ed25519,
    );
    final sig = crypto.Signature(
      signatureBytes,
      publicKey: pubKey,
    );

    return await _algorithm.verify(message, signature: sig);
  }
}
