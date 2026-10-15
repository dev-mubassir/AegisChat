import 'dart:typed_data';

import 'package:app/auth/app_lock.dart';
import 'package:app/chat/chat_service.dart';
import 'package:app/contacts/contact_manager.dart';
import 'package:app/storage/encrypted_message_store.dart';
import 'package:app/ui/chat_screen.dart';
import 'package:app/ui/contacts_screen.dart';
import 'package:app/ui/lock_screen.dart';
import 'package:app/ui/registration_screen.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

/// Root widget for the SecureChat application.
class MyApp extends StatelessWidget {
  final AppLockManager? appLockManager;
  final ContactManager? contactManager;
  final ChatService? chatService;
  final EncryptedMessageStore? messageStore;
  final Uint8List? localSigningKeyBytes;
  final bool isRegistered;

  const MyApp({
    super.key,
    this.appLockManager,
    this.contactManager,
    this.chatService,
    this.messageStore,
    this.localSigningKeyBytes,
    this.isRegistered = true,
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
        appLockManager: appLockManager,
        contactManager: contactManager,
        chatService: chatService,
        messageStore: messageStore,
        localSigningKeyBytes: localSigningKeyBytes ?? Uint8List(32),
        initialRegistered: isRegistered,
      ),
    );
  }
}

class SecureChatHome extends StatefulWidget {
  final AppLockManager? appLockManager;
  final ContactManager? contactManager;
  final ChatService? chatService;
  final EncryptedMessageStore? messageStore;
  final Uint8List localSigningKeyBytes;
  final bool initialRegistered;

  const SecureChatHome({
    super.key,
    this.appLockManager,
    this.contactManager,
    this.chatService,
    this.messageStore,
    required this.localSigningKeyBytes,
    required this.initialRegistered,
  });

  @override
  State<SecureChatHome> createState() => _SecureChatHomeState();
}

class _SecureChatHomeState extends State<SecureChatHome> {
  late bool _isRegistered;
  bool _isUnlocked = false;

  @override
  void initState() {
    super.initState();
    _isRegistered = widget.initialRegistered;
    // If no appLockManager is passed or not locked, start unlocked
    if (widget.appLockManager == null || !widget.appLockManager!.isLocked) {
      _isUnlocked = true;
    }
  }

  void _onUnlocked() {
    setState(() {
      _isUnlocked = true;
    });
  }

  void _onRegistered({
    required String inviteCode,
    required String username,
    required String deviceName,
    required String pin,
  }) {
    setState(() {
      _isRegistered = true;
      _isUnlocked = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (!_isRegistered) {
      return RegistrationScreen(
        onRegister: ({
          required String inviteCode,
          required String username,
          required String deviceName,
          required String pin,
        }) async {
          _onRegistered(
            inviteCode: inviteCode,
            username: username,
            deviceName: deviceName,
            pin: pin,
          );
        },
      );
    }

    if (widget.appLockManager != null && widget.appLockManager!.isLocked && !_isUnlocked) {
      return LockScreen(
        appLockManager: widget.appLockManager!,
        onUnlocked: _onUnlocked,
      );
    }

    if (widget.contactManager != null) {
      return ContactsScreen(
        contactManager: widget.contactManager!,
        localSigningKeyBytes: widget.localSigningKeyBytes,
        onContactSelected: (contact) {
          if (widget.chatService != null && widget.messageStore != null) {
            Navigator.of(context).push(
              MaterialPageRoute(
                builder: (_) => ChatScreen(
                  contact: contact,
                  chatService: widget.chatService!,
                  messageStore: widget.messageStore!,
                  contactManager: widget.contactManager!,
                  localSigningKeyBytes: widget.localSigningKeyBytes,
                ),
              ),
            );
          }
        },
      );
    }

    // Default placeholder for standalone preview
    return Scaffold(
      appBar: AppBar(title: const Text('SecureChat')),
      body: const Center(child: Text('SecureChat Ready')),
    );
  }
}
