import 'dart:async';
import 'dart:typed_data';

import 'package:app/chat/chat_service.dart';
import 'package:app/contacts/contact_manager.dart';
import 'package:app/storage/encrypted_message_store.dart';
import 'package:app/ui/safety_number_screen.dart';
import 'package:flutter/material.dart';

/// Conversation screen for exchanging end-to-end encrypted messages with a contact.
class ChatScreen extends StatefulWidget {
  final Contact contact;
  final ChatService chatService;
  final EncryptedMessageStore messageStore;
  final ContactManager contactManager;
  final Uint8List localSigningKeyBytes;

  const ChatScreen({
    super.key,
    required this.contact,
    required this.chatService,
    required this.messageStore,
    required this.contactManager,
    required this.localSigningKeyBytes,
  });

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final TextEditingController _textController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  List<ChatMessage> _messages = [];
  StreamSubscription<ChatMessage>? _messageSub;
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadMessages();
    _messageSub = widget.chatService.messageStream.listen((msg) {
      if (msg.conversationId == widget.contact.userId) {
        setState(() {
          // Replace if exists (e.g. status update) or append
          final index = _messages.indexWhere((m) => m.id == msg.id);
          if (index != -1) {
            _messages[index] = msg;
          } else {
            _messages.add(msg);
          }
        });
        _scrollToBottom();
      }
    });
  }

  @override
  void dispose() {
    _messageSub?.cancel();
    _textController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _loadMessages() async {
    final msgs = await widget.messageStore.getMessages(widget.contact.userId);
    if (mounted) {
      setState(() {
        _messages = msgs;
        _isLoading = false;
      });
      _scrollToBottom();
    }
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 250),
          curve: Curves.easeOut,
        );
      }
    });
  }

  Future<void> _sendMessage() async {
    final text = _textController.text.trim();
    if (text.isEmpty) return;
    _textController.clear();

    final rsaKey = widget.contact.rsaPublicKey;
    if (rsaKey == null) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Contact has no encryption public key')),
        );
      }
      return;
    }

    try {
      final sentMsg = await widget.chatService.sendMessage(
        recipientId: widget.contact.userId,
        text: text,
        recipientRsaPublicKey: rsaKey,
      );

      if (mounted) {
        setState(() {
          final index = _messages.indexWhere((m) => m.id == sentMsg.id);
          if (index != -1) {
            _messages[index] = sentMsg;
          } else {
            _messages.add(sentMsg);
          }
        });
        _scrollToBottom();
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to send message: $e')),
        );
      }
    }
  }

  Widget _buildStatusIcon(String status) {
    switch (status) {
      case 'sending':
        return const Icon(Icons.schedule, size: 14, color: Colors.grey);
      case 'sent':
        return const Icon(Icons.done, size: 14, color: Colors.grey);
      case 'delivered':
        return const Icon(Icons.done_all, size: 14, color: Colors.blue);
      default:
        return const SizedBox.shrink();
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(
          children: [
            CircleAvatar(
              radius: 18,
              child: Text(widget.contact.displayName.isNotEmpty
                  ? widget.contact.displayName[0].toUpperCase()
                  : '?'),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Flexible(
                        child: Text(
                          widget.contact.displayName,
                          style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(width: 6),
                      if (widget.contact.isVerified)
                        const Icon(Icons.verified, size: 16, color: Colors.green)
                      else
                        const Icon(Icons.help_outline, size: 16, color: Colors.grey),
                    ],
                  ),
                  Text(
                    widget.contact.isVerified ? 'Verified end-to-end' : 'Unverified identity',
                    style: TextStyle(
                      fontSize: 11,
                      color: widget.contact.isVerified ? Colors.green : Colors.grey,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            key: const Key('safety_numbers_action'),
            icon: const Icon(Icons.security),
            tooltip: 'Safety Numbers',
            onPressed: () {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => SafetyNumberScreen(
                    contact: widget.contact,
                    contactManager: widget.contactManager,
                    localSigningKeyBytes: widget.localSigningKeyBytes,
                  ),
                ),
              );
            },
          ),
        ],
      ),
      body: Column(
        children: [
          if (widget.contact.hasKeyChanged)
            Container(
              color: Colors.red.shade100,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: Row(
                children: [
                  const Icon(Icons.warning, color: Colors.red, size: 20),
                  const SizedBox(width: 8),
                  const Expanded(
                    child: Text(
                      'Warning: Contact security keys changed! Verify safety numbers.',
                      style: TextStyle(color: Colors.red, fontWeight: FontWeight.bold, fontSize: 12),
                    ),
                  ),
                  TextButton(
                    onPressed: () {
                      Navigator.of(context).push(
                        MaterialPageRoute(
                          builder: (_) => SafetyNumberScreen(
                            contact: widget.contact,
                            contactManager: widget.contactManager,
                            localSigningKeyBytes: widget.localSigningKeyBytes,
                          ),
                        ),
                      );
                    },
                    child: const Text('VERIFY', style: TextStyle(color: Colors.red)),
                  ),
                ],
              ),
            ),
          Expanded(
            child: _isLoading
                ? const Center(child: CircularProgressIndicator())
                : _messages.isEmpty
                    ? Center(
                        child: Text(
                          'No messages yet. Send a secure encrypted message!',
                          style: TextStyle(color: theme.colorScheme.onSurfaceVariant),
                        ),
                      )
                    : ListView.builder(
                        controller: _scrollController,
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 16),
                        itemCount: _messages.length,
                        itemBuilder: (context, index) {
                          final msg = _messages[index];
                          final isMe = msg.isOutgoing;

                          return Align(
                            alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
                            child: Container(
                              margin: const EdgeInsets.symmetric(vertical: 4),
                              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                              constraints: BoxConstraints(
                                maxWidth: MediaQuery.of(context).size.width * 0.75,
                              ),
                              decoration: BoxDecoration(
                                color: isMe
                                    ? theme.colorScheme.primaryContainer
                                    : theme.colorScheme.surfaceContainerHighest,
                                borderRadius: BorderRadius.only(
                                  topLeft: const Radius.circular(16),
                                  topRight: const Radius.circular(16),
                                  bottomLeft: isMe ? const Radius.circular(16) : const Radius.circular(4),
                                  bottomRight: isMe ? const Radius.circular(4) : const Radius.circular(16),
                                ),
                              ),
                              child: Column(
                                crossAxisAlignment:
                                    isMe ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    msg.content,
                                    style: TextStyle(
                                      fontSize: 15,
                                      color: isMe
                                          ? theme.colorScheme.onPrimaryContainer
                                          : theme.colorScheme.onSurface,
                                    ),
                                  ),
                                  const SizedBox(height: 4),
                                  Row(
                                    mainAxisSize: MainAxisSize.min,
                                    children: [
                                      Text(
                                        DateTime.fromMillisecondsSinceEpoch(msg.timestamp * 1000)
                                            .toLocal()
                                            .toString()
                                            .substring(11, 16),
                                        style: TextStyle(
                                          fontSize: 10,
                                          color: isMe
                                              ? theme.colorScheme.onPrimaryContainer.withAlpha(150)
                                              : theme.colorScheme.onSurfaceVariant,
                                        ),
                                      ),
                                      if (isMe) ...[
                                        const SizedBox(width: 4),
                                        _buildStatusIcon(msg.status),
                                      ],
                                    ],
                                  ),
                                ],
                              ),
                            ),
                          );
                        },
                      ),
          ),
          SafeArea(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: theme.colorScheme.surface,
                border: Border(top: BorderSide(color: theme.colorScheme.outlineVariant)),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      key: const Key('message_input'),
                      controller: _textController,
                      decoration: const InputDecoration(
                        hintText: 'Type an encrypted message...',
                        border: InputBorder.none,
                      ),
                      onSubmitted: (_) => _sendMessage(),
                    ),
                  ),
                  IconButton(
                    key: const Key('send_button'),
                    icon: const Icon(Icons.send),
                    color: theme.colorScheme.primary,
                    onPressed: _sendMessage,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
