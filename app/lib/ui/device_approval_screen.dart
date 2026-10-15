import 'package:app/auth/device_key.dart';
import 'package:app/auth/totp_service.dart';
import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

/// Screen for displaying new device approval QR code, or scanning and approving a new device from an existing device.
class DeviceApprovalScreen extends StatefulWidget {
  final TotpService totpService;
  final String oldDeviceId;
  final DeviceKey oldDeviceKey;
  final DeviceApprovalPayload? newDevicePayload;

  const DeviceApprovalScreen({
    super.key,
    required this.totpService,
    required this.oldDeviceId,
    required this.oldDeviceKey,
    this.newDevicePayload,
  });

  @override
  State<DeviceApprovalScreen> createState() => _DeviceApprovalScreenState();
}

class _DeviceApprovalScreenState extends State<DeviceApprovalScreen> {
  final TextEditingController _payloadController = TextEditingController();
  final TextEditingController _totpController = TextEditingController();

  DeviceApprovalPayload? _parsedPayload;
  bool _isApproving = false;
  String? _statusMessage;
  bool _isSuccess = false;

  @override
  void initState() {
    super.initState();
    if (widget.newDevicePayload != null) {
      _parsedPayload = widget.newDevicePayload;
    }
  }

  @override
  void dispose() {
    _payloadController.dispose();
    _totpController.dispose();
    super.dispose();
  }

  void _onPayloadChanged(String text) {
    try {
      final parsed = DeviceApprovalPayload.fromJsonString(text.trim());
      setState(() {
        _parsedPayload = parsed;
        _statusMessage = null;
      });
    } catch (_) {
      setState(() {
        _parsedPayload = null;
      });
    }
  }

  Future<void> _approveDevice() async {
    if (_parsedPayload == null) return;
    final totpCode = _totpController.text.trim();
    if (totpCode.length != 6) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter 6-digit TOTP or recovery code')),
      );
      return;
    }

    setState(() {
      _isApproving = true;
      _statusMessage = null;
    });

    try {
      await widget.totpService.approveNewDevice(
        oldDeviceId: widget.oldDeviceId,
        newDevice: _parsedPayload!,
        oldDeviceKey: widget.oldDeviceKey,
        totpCode: totpCode,
      );

      setState(() {
        _isApproving = false;
        _isSuccess = true;
        _statusMessage = 'Device approved successfully! New device can now login.';
      });
    } catch (e) {
      setState(() {
        _isApproving = false;
        _statusMessage = 'Approval failed: $e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final isNewDeviceDisplay = widget.newDevicePayload != null;

    return Scaffold(
      appBar: AppBar(
        title: Text(isNewDeviceDisplay ? 'New Device Approval QR' : 'Approve Another Device'),
      ),
      body: isNewDeviceDisplay ? _buildNewDeviceQrView() : _buildApproverView(),
    );
  }

  Widget _buildNewDeviceQrView() {
    final payloadJson = widget.newDevicePayload!.toJsonString();

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          const Text(
            'Scan on Your Existing Device',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          const Text(
            'Open SecureChat on your registered phone, go to Settings -> Approve Device, and scan this QR code.',
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 24),
          Center(
            child: Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(12),
              ),
              child: QrImageView(
                data: payloadJson,
                version: QrVersions.auto,
                size: 220.0,
              ),
            ),
          ),
          const SizedBox(height: 16),
          Text(
            'Device ID: ${widget.newDevicePayload!.newDeviceId}',
            style: const TextStyle(fontWeight: FontWeight.bold),
          ),
        ],
      ),
    );
  }

  Widget _buildApproverView() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Device Approval Code / Payload',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          TextField(
            key: const Key('approval_payload_input'),
            controller: _payloadController,
            maxLines: 3,
            decoration: const InputDecoration(
              hintText: 'Paste device approval JSON or payload from new device',
              border: OutlineInputBorder(),
            ),
            onChanged: _onPayloadChanged,
          ),
          const SizedBox(height: 16),
          if (_parsedPayload != null) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.blue.withAlpha(25),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.blue.withAlpha(100)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Device Verification Request',
                      style: TextStyle(fontWeight: FontWeight.bold, color: Colors.blue)),
                  const SizedBox(height: 4),
                  Text('User: ${_parsedPayload!.userId}'),
                  Text('New Device ID: ${_parsedPayload!.newDeviceId}'),
                ],
              ),
            ),
            const SizedBox(height: 16),
            const Text(
              'Enter Your TOTP or Recovery Code:',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            TextField(
              key: const Key('approval_totp_input'),
              controller: _totpController,
              keyboardType: TextInputType.text,
              maxLength: 16,
              decoration: const InputDecoration(
                hintText: '6-digit TOTP or 16-char recovery code',
                border: OutlineInputBorder(),
                counterText: '',
              ),
            ),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              height: 48,
              child: ElevatedButton(
                key: const Key('submit_approval_button'),
                onPressed: _isApproving ? null : _approveDevice,
                child: _isApproving
                    ? const CircularProgressIndicator()
                    : const Text('Sign & Approve Device'),
              ),
            ),
          ],
          if (_statusMessage != null) ...[
            const SizedBox(height: 16),
            Text(
              _statusMessage!,
              style: TextStyle(
                color: _isSuccess ? Colors.green : Colors.red,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ],
      ),
    );
  }
}
