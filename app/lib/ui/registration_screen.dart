import 'package:flutter/material.dart';

/// Registration / Onboarding screen where the user redeems an invite code, sets a username,
/// device name, and initial 6-digit PIN.
class RegistrationScreen extends StatefulWidget {
  final Future<void> Function({
    required String inviteCode,
    required String username,
    required String deviceName,
    required String pin,
  })? onRegister;

  final Future<void> Function({
    required String inviteCode,
    required String username,
    required String deviceName,
    required String pin,
    required String serverUrl,
  })? onRegisterWithServer;

  final String initialServerUrl;

  const RegistrationScreen({
    super.key,
    this.onRegister,
    this.onRegisterWithServer,
    this.initialServerUrl = 'http://192.168.29.122:8000',
  }) : assert(onRegister != null || onRegisterWithServer != null);

  @override
  State<RegistrationScreen> createState() => _RegistrationScreenState();
}

class _RegistrationScreenState extends State<RegistrationScreen> {
  late final TextEditingController _serverController =
      TextEditingController(text: widget.initialServerUrl);
  final TextEditingController _inviteController = TextEditingController();
  final TextEditingController _usernameController = TextEditingController();
  final TextEditingController _deviceController = TextEditingController(text: 'My Phone');
  final TextEditingController _pinController = TextEditingController();

  bool _isLoading = false;
  String? _errorMessage;

  @override
  void dispose() {
    _serverController.dispose();
    _inviteController.dispose();
    _usernameController.dispose();
    _deviceController.dispose();
    _pinController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final server = _serverController.text.trim();
    final invite = _inviteController.text.trim();
    final username = _usernameController.text.trim();
    final device = _deviceController.text.trim();
    final pin = _pinController.text.trim();

    if (server.isEmpty) {
      setState(() => _errorMessage = 'Please enter server relay URL');
      return;
    }

    if (invite.isEmpty) {
      setState(() => _errorMessage = 'Please enter an invite code');
      return;
    }
    if (username.isEmpty) {
      setState(() => _errorMessage = 'Please enter a username');
      return;
    }
    if (device.isEmpty) {
      setState(() => _errorMessage = 'Please enter a device name');
      return;
    }
    if (pin.length != 6 || !RegExp(r'^\d{6}$').hasMatch(pin)) {
      setState(() => _errorMessage = 'PIN must be exactly 6 digits');
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      if (widget.onRegisterWithServer != null) {
        await widget.onRegisterWithServer!(
          inviteCode: invite,
          username: username,
          deviceName: device,
          pin: pin,
          serverUrl: server,
        );
      } else {
        await widget.onRegister!(
          inviteCode: invite,
          username: username,
          deviceName: device,
          pin: pin,
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _errorMessage = 'Registration failed: $e';
        });
      }
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Register SecureChat'),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Welcome to SecureChat',
                style: theme.textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              Text(
                'Redeem your invite code to generate your cryptographic identity.',
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 24),
              TextField(
                key: const Key('server_url_input'),
                controller: _serverController,
                decoration: const InputDecoration(
                  labelText: 'Server Relay URL',
                  hintText: 'http://192.168.29.122:8000',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.dns),
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                key: const Key('invite_code_input'),
                controller: _inviteController,
                decoration: const InputDecoration(
                  labelText: 'Invite Code',
                  hintText: 'Enter secret invite token',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.key),
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                key: const Key('username_input'),
                controller: _usernameController,
                decoration: const InputDecoration(
                  labelText: 'Username',
                  hintText: 'e.g. alice',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.person),
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                key: const Key('device_name_input'),
                controller: _deviceController,
                decoration: const InputDecoration(
                  labelText: 'Device Name',
                  hintText: 'e.g. Pixel 8',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.phone_android),
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                key: const Key('pin_setup_input'),
                controller: _pinController,
                keyboardType: TextInputType.number,
                obscureText: true,
                maxLength: 6,
                decoration: const InputDecoration(
                  labelText: '6-digit App PIN',
                  hintText: '••••••',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.lock),
                  counterText: '',
                ),
              ),
              if (_errorMessage != null) ...[
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.errorContainer,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    _errorMessage!,
                    style: TextStyle(
                      color: theme.colorScheme.onErrorContainer,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ],
              const SizedBox(height: 28),
              FilledButton(
                key: const Key('register_button'),
                onPressed: _isLoading ? null : _submit,
                style: FilledButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                ),
                child: _isLoading
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                      )
                    : const Text('Create Cryptographic Account', style: TextStyle(fontSize: 16)),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
