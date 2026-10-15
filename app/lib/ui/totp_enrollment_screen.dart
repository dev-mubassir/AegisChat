import 'package:app/auth/totp_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

/// Screen for TOTP two-factor enrollment and single-use recovery code display.
class TotpEnrollmentScreen extends StatefulWidget {
  final TotpService totpService;
  final String accessToken;
  final VoidCallback? onCompleted;

  const TotpEnrollmentScreen({
    super.key,
    required this.totpService,
    required this.accessToken,
    this.onCompleted,
  });

  @override
  State<TotpEnrollmentScreen> createState() => _TotpEnrollmentScreenState();
}

class _TotpEnrollmentScreenState extends State<TotpEnrollmentScreen> {
  TotpEnrollmentData? _enrollmentData;
  bool _isLoading = true;
  String? _errorMessage;

  final TextEditingController _codeController = TextEditingController();
  bool _isConfirming = false;
  bool _isActivated = false;
  bool _hasBackedUpCodes = false;

  @override
  void initState() {
    super.initState();
    _startEnrollment();
  }

  @override
  void dispose() {
    _codeController.dispose();
    super.dispose();
  }

  Future<void> _startEnrollment() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final data = await widget.totpService.enrollTotp(accessToken: widget.accessToken);
      setState(() {
        _enrollmentData = data;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
        _isLoading = false;
      });
    }
  }

  Future<void> _confirmTotp() async {
    final code = _codeController.text.trim();
    if (code.length != 6) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter a 6-digit code')),
      );
      return;
    }

    setState(() {
      _isConfirming = true;
    });

    try {
      await widget.totpService.confirmTotp(
        accessToken: widget.accessToken,
        code: code,
      );
      setState(() {
        _isActivated = true;
        _isConfirming = false;
      });
    } catch (e) {
      setState(() {
        _isConfirming = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Verification failed: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Two-Factor Authentication'),
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_errorMessage != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.error_outline, color: Colors.red, size: 48),
              const SizedBox(height: 16),
              Text(_errorMessage!, textAlign: TextAlign.center),
              const SizedBox(height: 16),
              ElevatedButton(
                onPressed: _startEnrollment,
                child: const Text('Retry'),
              ),
            ],
          ),
        ),
      );
    }

    final data = _enrollmentData!;

    if (_isActivated) {
      return _buildRecoveryCodesView(data.recoveryCodes);
    }

    return _buildEnrollmentView(data);
  }

  Widget _buildEnrollmentView(TotpEnrollmentData data) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          const Text(
            'Scan QR Code with Authenticator App',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          const Text(
            'Use Google Authenticator, Aegis, or any compatible TOTP app.',
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
                data: data.otpauthUrl,
                version: QrVersions.auto,
                size: 200.0,
              ),
            ),
          ),
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              SelectableText(
                'Key: ${data.secret}',
                style: const TextStyle(fontWeight: FontWeight.bold, letterSpacing: 1.2),
              ),
              IconButton(
                icon: const Icon(Icons.copy, size: 20),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: data.secret));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Secret copied to clipboard')),
                  );
                },
              ),
            ],
          ),
          const SizedBox(height: 24),
          TextField(
            key: const Key('totp_code_input'),
            controller: _codeController,
            keyboardType: TextInputType.number,
            maxLength: 6,
            textAlign: TextAlign.center,
            style: const TextStyle(fontSize: 24, letterSpacing: 8, fontWeight: FontWeight.bold),
            decoration: const InputDecoration(
              hintText: '000000',
              border: OutlineInputBorder(),
              counterText: '',
            ),
          ),
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            height: 48,
            child: ElevatedButton(
              key: const Key('confirm_totp_button'),
              onPressed: _isConfirming ? null : _confirmTotp,
              child: _isConfirming
                  ? const CircularProgressIndicator()
                  : const Text('Verify & Activate'),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRecoveryCodesView(List<String> recoveryCodes) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.warning_amber_rounded, color: Colors.amber, size: 32),
              SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Save Your Recovery Codes',
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          const Text(
            'These 10 single-use recovery codes will allow you to access your account if you lose your authenticator. They will NEVER be shown again.',
            style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.grey.withAlpha(25),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.grey.withAlpha(80)),
            ),
            child: Column(
              children: recoveryCodes.map((code) {
                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4.0),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        code,
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 16),
                      ),
                      const Text(
                        'Single-use',
                        style: TextStyle(fontSize: 12, color: Colors.grey),
                      ),
                    ],
                  ),
                );
              }).toList(),
            ),
          ),
          const SizedBox(height: 24),
          CheckboxListTile(
            key: const Key('backup_confirm_checkbox'),
            title: const Text('I have safely recorded or printed these recovery codes.'),
            value: _hasBackedUpCodes,
            onChanged: (val) {
              setState(() {
                _hasBackedUpCodes = val ?? false;
              });
            },
          ),
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            height: 48,
            child: ElevatedButton(
              key: const Key('finish_totp_button'),
              onPressed: _hasBackedUpCodes
                  ? () {
                      if (widget.onCompleted != null) {
                        widget.onCompleted!();
                      } else {
                        Navigator.of(context).pop();
                      }
                    }
                  : null,
              child: const Text('Complete Setup'),
            ),
          ),
        ],
      ),
    );
  }
}
