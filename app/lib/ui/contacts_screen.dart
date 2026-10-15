import 'dart:typed_data';

import 'package:app/contacts/contact_manager.dart';
import 'package:flutter/material.dart';

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
        title: const Text('My Contact Card'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Share this JSON card with contacts so they can add you:'),
              const SizedBox(height: 12),
              SelectableText(
                jsonStr,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ],
          ),
        ),
        actions: [
          ElevatedButton.icon(
            icon: const Icon(Icons.copy),
            label: const Text('Copy JSON'),
            onPressed: () {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Contact card JSON copied!')),
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

  void _showAddContactDialog() {
    _qrInputController.clear();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Add Contact via QR'),
        content: TextField(
          key: const Key('add_contact_input'),
          controller: _qrInputController,
          maxLines: 4,
          decoration: const InputDecoration(
            hintText: 'Paste scanned contact card JSON',
            border: OutlineInputBorder(),
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
              try {
                final payload = ContactQrPayload.fromJsonString(_qrInputController.text.trim());
                await widget.contactManager.addOrUpdateFromQr(payload);
                if (mounted) {
                  setState(() {});
                }
                if (ctx.mounted) {
                  Navigator.of(ctx).pop();
                }
              } catch (e) {
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Invalid contact QR: $e')),
                  );
                }
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
          if (widget.myUserId != null && widget.myEncryptionPub != null)
            IconButton(
              key: const Key('my_contact_card_button'),
              icon: const Icon(Icons.badge_outlined),
              tooltip: 'My Contact Card',
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
