import 'dart:typed_data';

import 'package:app/contacts/contact_manager.dart';
import 'package:flutter/material.dart';

/// Screen for displaying and verifying the 60-digit symmetric safety number between two users.
class SafetyNumberScreen extends StatefulWidget {
  final Contact contact;
  final ContactManager contactManager;
  final Uint8List localSigningKeyBytes;

  const SafetyNumberScreen({
    super.key,
    required this.contact,
    required this.contactManager,
    required this.localSigningKeyBytes,
  });

  @override
  State<SafetyNumberScreen> createState() => _SafetyNumberScreenState();
}

class _SafetyNumberScreenState extends State<SafetyNumberScreen> {
  late bool _isVerified;
  late bool _hasKeyChanged;
  late String _safetyNumber;

  @override
  void initState() {
    super.initState();
    _isVerified = widget.contact.isVerified;
    _hasKeyChanged = widget.contact.hasKeyChanged;
    _safetyNumber = widget.contactManager.computeSafetyNumber(
      widget.contact.userId,
      widget.localSigningKeyBytes,
    );
  }

  Future<void> _toggleVerified() async {
    final newStatus = !_isVerified;
    await widget.contactManager.setVerified(widget.contact.userId, newStatus);
    setState(() {
      _isVerified = newStatus;
      if (newStatus) {
        _hasKeyChanged = false;
        widget.contact.hasKeyChanged = false;
      }
      widget.contact.isVerified = newStatus;
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: Text('Safety Number: ${widget.contact.displayName}'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (_hasKeyChanged) ...[
              Card(
                color: theme.colorScheme.errorContainer,
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Row(
                    children: [
                      Icon(Icons.warning_amber_rounded, color: theme.colorScheme.error, size: 32),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          'SECURITY WARNING: This contact\'s public keys have changed! Verify safety numbers before sending sensitive messages.',
                          style: TextStyle(
                            color: theme.colorScheme.onErrorContainer,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 20),
            ],
            Text(
              'Compare this 60-digit safety number with the one displayed on ${widget.contact.displayName}\'s device to ensure end-to-end encryption is not intercepted.',
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 24),
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: theme.colorScheme.outlineVariant),
              ),
              child: Text(
                _safetyNumber,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 2.0,
                  height: 1.6,
                ),
              ),
            ),
            const SizedBox(height: 32),
            Card(
              elevation: 0,
              color: _isVerified
                  ? Colors.green.withAlpha(25)
                  : theme.colorScheme.surfaceContainerHighest,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
                side: BorderSide(
                  color: _isVerified ? Colors.green : theme.colorScheme.outlineVariant,
                ),
              ),
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 12.0),
                child: Row(
                  children: [
                    Icon(
                      _isVerified ? Icons.verified : Icons.verified_outlined,
                      color: _isVerified ? Colors.green : theme.colorScheme.onSurfaceVariant,
                      size: 28,
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            _isVerified ? 'Marked as Verified' : 'Unverified Contact',
                            style: theme.textTheme.titleMedium?.copyWith(
                              fontWeight: FontWeight.bold,
                              color: _isVerified ? Colors.green : null,
                            ),
                          ),
                          Text(
                            _isVerified
                                ? 'Identity confirmed with safety number'
                                : 'Tap button below once numbers match',
                            style: theme.textTheme.bodySmall,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),
            FilledButton.icon(
              key: const Key('toggle_verified_screen_button'),
              onPressed: _toggleVerified,
              icon: Icon(_isVerified ? Icons.close : Icons.check),
              label: Text(_isVerified ? 'Mark as Unverified' : 'Mark as Verified'),
              style: FilledButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 14),
                backgroundColor: _isVerified ? Colors.grey.shade700 : null,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
