import 'dart:typed_data';

import 'package:app/contacts/contact_manager.dart';
import 'package:app/ui/qr_scan_screen.dart';
import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

/// Screen displaying the contact list with verification status, key change warnings, and safety numbers.
class ContactsScreen extends StatefulWidget {
  final ContactManager contactManager;
  final Uint8List localSigningKeyBytes;
  final void Function(Contact contact)? onContactSelected;
  final String? myUserId;
  final String? myEncryptionPub;

  const ContactsScreen({
    super.key,
    required this.contactManager,
    required this.localSigningKeyBytes,
    this.onContactSelected,
    this.myUserId,
    this.myEncryptionPub,
  });

  @override
  State<ContactsScreen> createState() => _ContactsScreenState();
}

class _ContactsScreenState extends State<ContactsScreen> {
  final TextEditingController _qrInputController = TextEditingController();

  @override
  void initState() {
    super.initState();
    widget.contactManager.load().then((_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _qrInputController.dispose();
    super.dispose();
  }

  void _showMyContactCardDialog() {
    if (widget.myUserId == null || widget.myEncryptionPub == null) return;
    final signingHex = widget.localSigningKeyBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    final card = ContactQrPayload(
      userId: widget.myUserId!,
      displayName: widget.myUserId!,
      signingPublicKeyHex: signingHex,
      encryptionPublicKeyPem: widget.myEncryptionPub!,
    );
    final jsonStr = card.toJsonString();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('My QR Code (@${widget.myUserId})'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(16),
                  boxShadow: const [
                    BoxShadow(color: Colors.black12, blurRadius: 8, spreadRadius: 2),
                  ],
                ),
                child: QrImageView(
                  data: jsonStr,
                  version: QrVersions.auto,
                  size: 220.0,
                  backgroundColor: Colors.white,
                ),
              ),
              const SizedBox(height: 14),
              const Text(
                'Let other users scan this QR code with their camera to add you instantly.',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 13, color: Colors.grey),
              ),
            ],
          ),
        ),
        actions: [
          ElevatedButton.icon(
            icon: const Icon(Icons.copy, size: 18),
            label: const Text('Copy Card Code'),
            onPressed: () {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Contact card code copied!')),
              );
              Navigator.of(ctx).pop();
            },
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Future<void> _scanQrCode() async {
    final scannedCode = await Navigator.of(context).push<String>(
      MaterialPageRoute(builder: (_) => const QrScanScreen()),
    );
    if (scannedCode != null && scannedCode.trim().isNotEmpty) {
      await _processContactPayload(scannedCode.trim());
    }
  }

  Future<void> _processContactPayload(String rawCode) async {
    try {
      final payload = ContactQrPayload.fromJsonString(rawCode.trim());
      final contact = await widget.contactManager.addOrUpdateFromQr(payload);
      if (mounted) {
        setState(() {});
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Added contact: ${contact.displayName} (@${contact.userId})'),
            backgroundColor: Colors.green.shade700,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Invalid contact QR code: $e'),
            backgroundColor: Colors.red.shade700,
          ),
        );
      }
    }
  }

  void _showAddContactDialog() {
    _qrInputController.clear();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Add Contact via QR'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              ElevatedButton.icon(
                key: const Key('scan_camera_dialog_button'),
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  backgroundColor: Theme.of(context).colorScheme.primary,
                  foregroundColor: Colors.white,
                ),
                icon: const Icon(Icons.qr_code_scanner),
                label: const Text('Scan with Camera', style: TextStyle(fontWeight: FontWeight.bold)),
                onPressed: () {
                  Navigator.of(ctx).pop();
                  _scanQrCode();
                },
              ),
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 12),
                child: Row(
                  children: [
                    Expanded(child: Divider()),
                    Padding(
                      padding: EdgeInsets.symmetric(horizontal: 8),
                      child: Text('OR PASTE CODE', style: TextStyle(fontSize: 11, color: Colors.grey)),
                    ),
                    Expanded(child: Divider()),
                  ],
                ),
              ),
              TextField(
                key: const Key('add_contact_input'),
                controller: _qrInputController,
                maxLines: 4,
                decoration: const InputDecoration(
                  hintText: 'Paste scanned contact card JSON',
                  border: OutlineInputBorder(),
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            key: const Key('submit_add_contact'),
            onPressed: () async {
              final text = _qrInputController.text.trim();
              Navigator.of(ctx).pop();
              if (text.isNotEmpty) {
                await _processContactPayload(text);
              }
            },
            child: const Text('Add Contact'),
          ),
        ],
      ),
    );
  }

  void _showSafetyNumberDialog(Contact contact) {
    final safetyNumber = widget.contactManager.computeSafetyNumber(
      contact.userId,
      widget.localSigningKeyBytes,
    );

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => AlertDialog(
          title: Text('Safety Number: ${contact.displayName}'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (contact.hasKeyChanged) ...[
                  Container(
                    padding: const EdgeInsets.all(12),
                    margin: const EdgeInsets.only(bottom: 16),
                    decoration: BoxDecoration(
                      color: Colors.red.withAlpha(30),
                      border: Border.all(color: Colors.red),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: const Row(
                      children: [
                        Icon(Icons.warning, color: Colors.red),
                        SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'WARNING: Security keys have changed! Verify safety number with your contact in person or via trusted channel.',
                            style: TextStyle(color: Colors.red, fontWeight: FontWeight.bold),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
                const Text(
                  'Compare this 60-digit number with the number on your contact\'s phone:',
                  style: TextStyle(fontSize: 14),
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.grey.withAlpha(25),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Center(
                    child: Text(
                      safetyNumber,
                      textAlign: TextAlign.center,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                        letterSpacing: 1.5,
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                Row(
                  children: [
                    Icon(
                      contact.isVerified ? Icons.verified : Icons.help_outline,
                      color: contact.isVerified ? Colors.green : Colors.grey,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      contact.isVerified ? 'Status: Verified' : 'Status: Unverified',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        color: contact.isVerified ? Colors.green : Colors.grey,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Close'),
            ),
            ElevatedButton(
              key: const Key('toggle_verified_button'),
              onPressed: () async {
                final newStatus = !contact.isVerified;
                await widget.contactManager.setVerified(contact.userId, newStatus);
                setDialogState(() {
                  contact.isVerified = newStatus;
                  if (newStatus) contact.hasKeyChanged = false;
                });
                setState(() {});
              },
              child: Text(contact.isVerified ? 'Mark Unverified' : 'Mark as Verified'),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final contacts = widget.contactManager.getAllContacts();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Contacts'),
        actions: [
          IconButton(
            key: const Key('scan_contact_qr_button'),
            icon: const Icon(Icons.qr_code_scanner),
            tooltip: 'Scan Contact QR',
            onPressed: _scanQrCode,
          ),
          if (widget.myUserId != null && widget.myEncryptionPub != null)
            IconButton(
              key: const Key('my_contact_card_button'),
              icon: const Icon(Icons.qr_code_2),
              tooltip: 'My QR Code',
              onPressed: _showMyContactCardDialog,
            ),
          IconButton(
            key: const Key('add_contact_button'),
            icon: const Icon(Icons.person_add),
            tooltip: 'Add Contact',
            onPressed: _showAddContactDialog,
          ),
        ],
      ),
      body: contacts.isEmpty
          ? const Center(child: Text('No contacts yet. Tap + to add via QR code.'))
          : ListView.builder(
              itemCount: contacts.length,
              itemBuilder: (ctx, i) {
                final c = contacts[i];
                return ListTile(
                  key: Key('contact_tile_${c.userId}'),
                  leading: CircleAvatar(child: Text(c.displayName[0].toUpperCase())),
                  title: Row(
                    children: [
                      Text(c.displayName, style: const TextStyle(fontWeight: FontWeight.bold)),
                      const SizedBox(width: 6),
                      if (c.hasKeyChanged)
                        const Icon(Icons.warning, color: Colors.red, size: 18)
                      else if (c.isVerified)
                        const Icon(Icons.verified, color: Colors.green, size: 18)
                      else
                        const Icon(Icons.help_outline, color: Colors.grey, size: 18),
                    ],
                  ),
                  subtitle: Text(
                    c.hasKeyChanged
                        ? 'SECURITY ALERT: Key changed!'
                        : (c.isVerified ? 'Verified Contact' : 'Unverified Contact'),
                    style: TextStyle(
                      color: c.hasKeyChanged ? Colors.red : null,
                      fontWeight: c.hasKeyChanged ? FontWeight.bold : null,
                    ),
                  ),
                  trailing: IconButton(
                    icon: const Icon(Icons.security),
                    onPressed: () => _showSafetyNumberDialog(c),
                  ),
                  onTap: () {
                    if (widget.onContactSelected != null) {
                      widget.onContactSelected!(c);
                    } else {
                      _showSafetyNumberDialog(c);
                    }
                  },
                );
              },
            ),
    );
  }
}
