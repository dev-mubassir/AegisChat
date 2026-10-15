import 'package:app/auth/app_lock.dart';
import 'package:flutter/material.dart';

/// Screen displayed when the app is locked by timeout, manual lock, or app launch.
class LockScreen extends StatefulWidget {
  final AppLockManager appLockManager;
  final VoidCallback onUnlocked;

  const LockScreen({
    super.key,
    required this.appLockManager,
    required this.onUnlocked,
  });

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final TextEditingController _pinController = TextEditingController();
  String? _errorMessage;
  bool _isAuthenticating = false;

  @override
  void dispose() {
    _pinController.dispose();
    super.dispose();
  }

  Future<void> _verifyPin() async {
    final pin = _pinController.text.trim();
    if (pin.length != 6) {
      setState(() {
        _errorMessage = 'PIN must be exactly 6 digits';
      });
      return;
    }

    setState(() {
      _isAuthenticating = true;
      _errorMessage = null;
    });

    try {
      final success = await widget.appLockManager.verifyPin(pin);
      if (success) {
        if (mounted) {
          widget.onUnlocked();
        }
      } else {
        final remaining = await widget.appLockManager.getLockoutRemainingSeconds();
        setState(() {
          _errorMessage = remaining > 0
              ? 'Incorrect PIN. Rate-limited for ${remaining}s.'
              : 'Incorrect PIN. Please try again.';
          _pinController.clear();
        });
      }
    } on AppLockoutException catch (e) {
      setState(() {
        _errorMessage = 'Rate limited! Please wait ${e.remainingSeconds}s.';
        _pinController.clear();
      });
    } on AppWipedException catch (e) {
      setState(() {
        _errorMessage = 'SECURITY ALERT: ${e.message}';
        _pinController.clear();
      });
    } catch (e) {
      setState(() {
        _errorMessage = 'Authentication error: $e';
        _pinController.clear();
      });
    } finally {
      if (mounted) {
        setState(() {
          _isAuthenticating = false;
        });
      }
    }
  }

  Future<void> _unlockWithBiometrics() async {
    setState(() {
      _isAuthenticating = true;
      _errorMessage = null;
    });

    try {
      final success = await widget.appLockManager.authenticateWithBiometrics();
      if (success) {
        if (mounted) {
          widget.onUnlocked();
        }
      } else {
        setState(() {
          _errorMessage = 'Biometric authentication was not successful.';
        });
      }
    } catch (e) {
      setState(() {
        _errorMessage = 'Biometric error: $e';
      });
    } finally {
      if (mounted) {
        setState(() {
          _isAuthenticating = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      backgroundColor: theme.colorScheme.surface,
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 32.0),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Container(
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.primaryContainer,
                    shape: BoxShape.circle,
                  ),
                  child: Icon(
                    Icons.lock_outline,
                    size: 64,
                    color: theme.colorScheme.onPrimaryContainer,
                  ),
                ),
                const SizedBox(height: 24),
                Text(
                  'SecureChat Locked',
                  style: theme.textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  'Enter your 6-digit PIN to access encrypted messages',
                  textAlign: TextAlign.center,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                const SizedBox(height: 32),
                SizedBox(
                  width: 220,
                  child: TextField(
                    key: const Key('pin_input'),
                    controller: _pinController,
                    keyboardType: TextInputType.number,
                    obscureText: true,
                    maxLength: 6,
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                      letterSpacing: 16,
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                    ),
                    decoration: const InputDecoration(
                      counterText: '',
                      hintText: '••••••',
                      border: OutlineInputBorder(),
                    ),
                    onSubmitted: (_) => _verifyPin(),
                  ),
                ),
                if (_errorMessage != null) ...[
                  const SizedBox(height: 16),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                    decoration: BoxDecoration(
                      color: theme.colorScheme.errorContainer,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Text(
                      _errorMessage!,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: theme.colorScheme.onErrorContainer,
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
                const SizedBox(height: 28),
                SizedBox(
                  width: 220,
                  height: 48,
                  child: FilledButton(
                    key: const Key('unlock_button'),
                    onPressed: _isAuthenticating ? null : _verifyPin,
                    child: _isAuthenticating
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                          )
                        : const Text('Unlock', style: TextStyle(fontSize: 16)),
                  ),
                ),
                const SizedBox(height: 16),
                IconButton(
                  key: const Key('biometric_unlock_button'),
                  icon: const Icon(Icons.fingerprint, size: 40),
                  tooltip: 'Unlock with Biometrics',
                  color: theme.colorScheme.primary,
                  onPressed: _isAuthenticating ? null : _unlockWithBiometrics,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
