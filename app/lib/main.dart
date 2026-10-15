import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:app/auth/app_lock.dart';
import 'package:app/auth/device_key.dart';
import 'package:app/auth/login_client.dart';
import 'package:app/chat/chat_service.dart';
import 'package:app/contacts/contact_manager.dart';
import 'package:app/crypto/asymmetric.dart';
import 'package:app/crypto/keystore.dart';
import 'package:app/storage/encrypted_message_store.dart';
import 'package:app/ui/chat_screen.dart';
import 'package:app/ui/contacts_screen.dart';
import 'package:app/ui/lock_screen.dart';
import 'package:app/ui/registration_screen.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';
import 'package:pointycastle/asymmetric/api.dart' show RSAPublicKey, RSAPrivateKey;

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const MyApp());
}

/// Root widget for the SecureChat application.
class MyApp extends StatelessWidget {
  final KeyStore? keyStore;
  final AppLockManager? appLockManager;
  final ContactManager? contactManager;
  final ChatService? chatService;
  final EncryptedMessageStore? messageStore;
  final Uint8List? localSigningKeyBytes;
  final bool? isRegistered;

  const MyApp({
    super.key,
    this.keyStore,
    this.appLockManager,
    this.contactManager,
    this.chatService,
    this.messageStore,
    this.localSigningKeyBytes,
    this.isRegistered,
  });

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SecureChat',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1E88E5),
          brightness: Brightness.light,
        ),
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1E88E5),
          brightness: Brightness.dark,
        ),
      ),
      home: SecureChatHome(
        keyStore: keyStore,
        appLockManager: appLockManager,
        contactManager: contactManager,
        chatService: chatService,
        messageStore: messageStore,
        localSigningKeyBytes: localSigningKeyBytes,
        initialRegistered: isRegistered,
      ),
    );
  }
}

class SecureChatHome extends StatefulWidget {
  final KeyStore? keyStore;
  final AppLockManager? appLockManager;
  final ContactManager? contactManager;
  final ChatService? chatService;
  final EncryptedMessageStore? messageStore;
  final Uint8List? localSigningKeyBytes;
  final bool? initialRegistered;

  const SecureChatHome({
    super.key,
    this.keyStore,
    this.appLockManager,
    this.contactManager,
    this.chatService,
    this.messageStore,
    this.localSigningKeyBytes,
    this.initialRegistered,
  });

  @override
  State<SecureChatHome> createState() => _SecureChatHomeState();
}

class _SecureChatHomeState extends State<SecureChatHome> {
  late KeyStore _keyStore;
  AppLockManager? _appLockManager;
  ContactManager? _contactManager;
  ChatService? _chatService;
  EncryptedMessageStore? _messageStore;
  Uint8List _localSigningKeyBytes = Uint8List(32);
  String? _currentUserId;
  String? _currentEncryptionPub;

  bool _isLoading = true;
  bool _isRegistered = false;
  bool _isUnlocked = false;
  String? _initError;

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    // 1. If mock/test services are passed, use them directly
    if (widget.contactManager != null) {
      _keyStore = widget.keyStore ?? InMemoryKeyStore();
      _appLockManager = widget.appLockManager;
      _contactManager = widget.contactManager;
      _chatService = widget.chatService;
      _messageStore = widget.messageStore;
      _localSigningKeyBytes = widget.localSigningKeyBytes ?? Uint8List(32);
      _isRegistered = widget.initialRegistered ?? true;
      _isUnlocked = widget.appLockManager == null || !widget.appLockManager!.isLocked;
      setState(() {
        _isLoading = false;
      });
      return;
    }

    // 2. Real application runtime initialization
    try {
      _keyStore = widget.keyStore ?? SecureKeyStore();
      _appLockManager = widget.appLockManager ?? AppLockManager(keyStore: _keyStore);

      final storedUserId = await _keyStore.read('auth_user_id');
      if (storedUserId == null || storedUserId.isEmpty) {
        // Not registered yet
        setState(() {
          _isRegistered = false;
          _isLoading = false;
        });
        return;
      }

      // User is registered: check if locked
      _isRegistered = true;
      if (_appLockManager!.isLocked) {
        setState(() {
          _isUnlocked = false;
          _isLoading = false;
        });
        return;
      }

      // App is unlocked: initialize services
      await _initializeRuntimeServices(storedUserId);
      setState(() {
        _isUnlocked = true;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _initError = e.toString();
        _isLoading = false;
      });
    }
  }

  Future<void> _initializeRuntimeServices(String userId) async {
    final serverUrl = await _keyStore.read('server_url') ?? 'http://192.168.29.122:8000';
    final deviceId = await _keyStore.read('auth_device_id') ?? 'My Phone';

    Directory docDir;
    try {
      docDir = await getApplicationDocumentsDirectory();
    } catch (_) {
      docDir = Directory.current;
    }

    final contactManager = ContactManager(file: File('${docDir.path}/contacts.json'));
    await contactManager.load();

    final messageStore = EncryptedMessageStore(
      file: File('${docDir.path}/messages.json'),
      keyStore: _keyStore,
    );

    // Retrieve or generate session keys
    final devKey = SoftwareDeviceKey.generate(allowInReleaseForTesting: true);
    final modStr = await _keyStore.read('rsa_modulus');
    final privExpStr = await _keyStore.read('rsa_priv_exponent');
    final pStr = await _keyStore.read('rsa_p');
    final qStr = await _keyStore.read('rsa_q');
    RsaKeyPair rsaPair;
    if (modStr != null && privExpStr != null && pStr != null && qStr != null) {
      final mod = BigInt.parse(modStr, radix: 16);
      final exp = BigInt.parse(await _keyStore.read('rsa_exponent') ?? '10001', radix: 16);
      final privExp = BigInt.parse(privExpStr, radix: 16);
      final p = BigInt.parse(pStr, radix: 16);
      final q = BigInt.parse(qStr, radix: 16);
      final pub = RSAPublicKey(mod, exp);
      final priv = RSAPrivateKey(mod, privExp, p, q);
      rsaPair = RsaKeyPair(publicKey: pub, privateKey: priv);
    } else {
      final rsa = RsaOaep();
      rsaPair = await rsa.generateKeyPair();
    }
    final signer = MessageSigner();
    final signingPair = await signer.generateKeyPair();
    final signingPubBytes = await signer.getPublicKeyBytes(signingPair);

    final loginClient = LoginClient(
      baseUrl: serverUrl,
      keyStore: _keyStore,
      deviceKey: devKey,
    );

    String token = '';
    try {
      final tokens = await loginClient.login(userId: userId, deviceId: deviceId);
      token = tokens.accessToken;
    } catch (_) {
      token = await loginClient.getAccessToken() ?? '';
    }

    final wsUri = Uri.parse(serverUrl);
    final wsScheme = wsUri.scheme == 'https' ? 'wss' : 'ws';
    final wsBaseUrl = '$wsScheme://${wsUri.host}:${wsUri.port}';

    final chatService = ChatService(
      wsBaseUrl: wsBaseUrl,
      getAccessToken: () => token,
      myUserId: userId,
      mySigningKeyPair: signingPair,
      myRsaPrivateKey: rsaPair.privateKey,
      messageStore: messageStore,
      getSenderSigningPublicKey: (senderId) async {
        final c = contactManager.getContact(senderId);
        return c?.signingKeyBytes;
      },
    );
    chatService.connect();

    _contactManager = contactManager;
    _chatService = chatService;
    _messageStore = messageStore;
    _localSigningKeyBytes = signingPubBytes;
    _currentUserId = userId;
    _currentEncryptionPub = await _keyStore.read('rsa_pub_hex') ?? formatRsaPublicKeyHex(rsaPair.publicKey);
  }

  void _onUnlocked() async {
    final userId = await _keyStore.read('auth_user_id');
    if (userId != null && _chatService == null) {
      await _initializeRuntimeServices(userId);
    }
    setState(() {
      _isUnlocked = true;
    });
  }

  Future<void> _onRegister({
    required String inviteCode,
    required String username,
    required String deviceName,
    required String pin,
    String? serverUrl,
  }) async {
    final effectiveServerUrl = (serverUrl != null && serverUrl.isNotEmpty)
        ? serverUrl
        : 'http://192.168.29.122:8000';

    // 1. Generate cryptographic keys
    final devKey = SoftwareDeviceKey.generate(allowInReleaseForTesting: true);
    final devPubPem = await devKey.getPublicKeyPem();

    final rsa = RsaOaep();
    final rsaPair = await rsa.generateKeyPair();

    final signer = MessageSigner();
    final signingPair = await signer.generateKeyPair();
    final signingPubBytes = await signer.getPublicKeyBytes(signingPair);

    // 2. Call server registration endpoint
    final regUri = Uri.parse('$effectiveServerUrl/register');
    final regResp = await http.post(
      regUri,
      headers: {'content-type': 'application/json'},
      body: json.encode({
        'invite_code': inviteCode,
        'user_id': username,
        'device_id': deviceName,
        'device_signing_pub': devPubPem,
        'device_encryption_pub': 'RSA_2048_PUB',
      }),
    );

    if (regResp.statusCode != 200) {
      String msg = regResp.body;
      try {
        final map = json.decode(regResp.body) as Map<String, dynamic>;
        if (map.containsKey('detail')) msg = map['detail'].toString();
      } catch (_) {}
      throw Exception(msg);
    }

    // 3. Setup PIN and save credentials
    _appLockManager ??= AppLockManager(keyStore: _keyStore);
    await _appLockManager!.setupPin(pin);

    await _keyStore.write('server_url', effectiveServerUrl);
    await _keyStore.write('auth_user_id', username);
    await _keyStore.write('auth_device_id', deviceName);

    // 4. Log in via challenge-response
    final loginClient = LoginClient(
      baseUrl: effectiveServerUrl,
      keyStore: _keyStore,
      deviceKey: devKey,
    );
    final tokens = await loginClient.login(userId: username, deviceId: deviceName);

    // 5. Initialize storage and chat service
    Directory docDir;
    try {
      docDir = await getApplicationDocumentsDirectory();
    } catch (_) {
      docDir = Directory.current;
    }

    final contactManager = ContactManager(file: File('${docDir.path}/contacts.json'));
    await contactManager.load();

    final messageStore = EncryptedMessageStore(
      file: File('${docDir.path}/messages.json'),
      keyStore: _keyStore,
    );

    final wsUri = Uri.parse(effectiveServerUrl);
    final wsScheme = wsUri.scheme == 'https' ? 'wss' : 'ws';
    final wsBaseUrl = '$wsScheme://${wsUri.host}:${wsUri.port}';

    final chatService = ChatService(
      wsBaseUrl: wsBaseUrl,
      getAccessToken: () => tokens.accessToken,
      myUserId: username,
      mySigningKeyPair: signingPair,
      myRsaPrivateKey: rsaPair.privateKey,
      messageStore: messageStore,
      getSenderSigningPublicKey: (senderId) async {
        final c = contactManager.getContact(senderId);
        return c?.signingKeyBytes;
      },
    );
    chatService.connect();

    final rsaPubHex = formatRsaPublicKeyHex(rsaPair.publicKey);
    await _keyStore.write('rsa_modulus', rsaPair.publicKey.modulus!.toRadixString(16));
    await _keyStore.write('rsa_exponent', rsaPair.publicKey.exponent!.toRadixString(16));
    await _keyStore.write('rsa_priv_exponent', rsaPair.privateKey.privateExponent!.toRadixString(16));
    await _keyStore.write('rsa_p', rsaPair.privateKey.p!.toRadixString(16));
    await _keyStore.write('rsa_q', rsaPair.privateKey.q!.toRadixString(16));
    await _keyStore.write('rsa_pub_hex', rsaPubHex);

    setState(() {
      _contactManager = contactManager;
      _chatService = chatService;
      _messageStore = messageStore;
      _localSigningKeyBytes = signingPubBytes;
      _currentUserId = username;
      _currentEncryptionPub = rsaPubHex;
      _isRegistered = true;
      _isUnlocked = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return Scaffold(
        appBar: AppBar(title: const Text('SecureChat')),
        body: const Center(child: Text('SecureChat Ready')),
      );
    }

    if (_initError != null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Error')),
        body: Center(child: Text('Initialization failed: $_initError')),
      );
    }

    if (!_isRegistered) {
      return RegistrationScreen(
        onRegisterWithServer: _onRegister,
      );
    }

    if (_appLockManager != null && _appLockManager!.isLocked && !_isUnlocked) {
      return LockScreen(
        appLockManager: _appLockManager!,
        onUnlocked: _onUnlocked,
      );
    }

    if (_contactManager != null) {
      return ContactsScreen(
        contactManager: _contactManager!,
        localSigningKeyBytes: _localSigningKeyBytes,
        myUserId: _currentUserId,
        myEncryptionPub: _currentEncryptionPub,
        onContactSelected: (contact) {
          if (_chatService != null && _messageStore != null) {
            Navigator.of(context).push(
              MaterialPageRoute(
                builder: (_) => ChatScreen(
                  contact: contact,
                  chatService: _chatService!,
                  messageStore: _messageStore!,
                  contactManager: _contactManager!,
                  localSigningKeyBytes: _localSigningKeyBytes,
                ),
              ),
            );
          }
        },
      );
    }

    return const Scaffold(
      body: Center(child: Text('SecureChat Ready')),
    );
  }
}
