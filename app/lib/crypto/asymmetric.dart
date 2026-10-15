import 'dart:convert';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

/// Serializes an RSAPublicKey to a compact hex string representation "modulusHex:exponentHex".
String formatRsaPublicKeyHex(RSAPublicKey key) {
  return '${key.modulus!.toRadixString(16)}:${key.exponent!.toRadixString(16)}';
}

/// Parses an RSA public key from:
/// 1. "modulusHex:exponentHex" (simple compact serialization)
/// 2. PEM format (SubjectPublicKeyInfo or PKCS#1)
/// 3. Raw Base64 DER
RSAPublicKey? parseRsaPublicKey(String input) {
  final clean = input.trim();
  if (clean.contains(':')) {
    final parts = clean.split(':');
    if (parts.length == 2) {
      try {
        final mod = BigInt.parse(parts[0], radix: 16);
        final exp = BigInt.parse(parts[1], radix: 16);
        return RSAPublicKey(mod, exp);
      } catch (_) {}
    }
  }

  try {
    String b64 = clean;
    if (clean.contains('-----BEGIN')) {
      final lines = clean.split('\n').where((l) => !l.startsWith('-----')).join();
      b64 = lines.replaceAll(RegExp(r'\s+'), '');
    }
    final bytes = base64.decode(b64);
    final parser = ASN1Parser(bytes);
    final topSeq = parser.nextObject() as ASN1Sequence;

    if (topSeq.elements != null &&
        topSeq.elements!.length == 2 &&
        topSeq.elements![1] is ASN1BitString) {
      final bitString = topSeq.elements![1] as ASN1BitString;
      final innerBytes = bitString.stringValues;
      if (innerBytes != null) {
        final innerParser = ASN1Parser(Uint8List.fromList(innerBytes));
        final rsaSeq = innerParser.nextObject() as ASN1Sequence;
        final mod = (rsaSeq.elements![0] as ASN1Integer).integer;
        final exp = (rsaSeq.elements![1] as ASN1Integer).integer;
        if (mod != null && exp != null) {
          return RSAPublicKey(mod, exp);
        }
      }
    } else if (topSeq.elements != null &&
        topSeq.elements!.length >= 2 &&
        topSeq.elements![0] is ASN1Integer) {
      final mod = (topSeq.elements![0] as ASN1Integer).integer;
      final exp = (topSeq.elements![1] as ASN1Integer).integer;
      if (mod != null && exp != null) {
        return RSAPublicKey(mod, exp);
      }
    }
  } catch (_) {}

  return null;
}

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
