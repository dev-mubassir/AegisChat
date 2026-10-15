import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

/// Full-screen camera QR scanner with viewfinder overlay, torch toggle, and fallback paste option.
class QrScanScreen extends StatefulWidget {
  const QrScanScreen({super.key});

  @override
  State<QrScanScreen> createState() => _QrScanScreenState();
}

class _QrScanScreenState extends State<QrScanScreen> {
  final MobileScannerController _controller = MobileScannerController();
  bool _hasDetected = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onBarcodeDetected(BarcodeCapture capture) {
    if (_hasDetected) return;
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue;
      if (raw != null && raw.trim().isNotEmpty) {
        _hasDetected = true;
        Navigator.of(context).pop(raw.trim());
        break;
      }
    }
  }

  void _showPasteFallbackDialog() {
    final textController = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Paste Contact Code'),
        content: TextField(
          key: const Key('paste_fallback_input'),
          controller: textController,
          maxLines: 4,
          decoration: const InputDecoration(
            hintText: 'Paste contact card JSON',
            border: OutlineInputBorder(),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              final text = textController.text.trim();
              Navigator.of(ctx).pop();
              if (text.isNotEmpty) {
                Navigator.of(context).pop(text);
              }
            },
            child: const Text('Submit'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        foregroundColor: Colors.white,
        title: const Text('Scan Contact QR Code'),
        actions: [
          IconButton(
            icon: const Icon(Icons.flash_on, color: Colors.white),
            onPressed: () => _controller.toggleTorch(),
          ),
          IconButton(
            icon: const Icon(Icons.flip_camera_ios, color: Colors.white),
            onPressed: () => _controller.switchCamera(),
          ),
        ],
      ),
      body: Stack(
        alignment: Alignment.center,
        children: [
          // 1. Live camera viewfinder
          MobileScanner(
            controller: _controller,
            onDetect: _onBarcodeDetected,
          ),

          // 2. Translucent viewfinder cutout overlay
          ColorFiltered(
            colorFilter: ColorFilter.mode(
              Colors.black.withAlpha(150),
              BlendMode.srcOut,
            ),
            child: Stack(
              children: [
                Container(
                  decoration: const BoxDecoration(
                    color: Colors.transparent,
                  ),
                ),
                Align(
                  alignment: Alignment.center,
                  child: Container(
                    width: 260,
                    height: 260,
                    decoration: BoxDecoration(
                      color: Colors.black,
                      borderRadius: BorderRadius.circular(20),
                    ),
                  ),
                ),
              ],
            ),
          ),

          // 3. Glowing bounding frame for the viewfinder
          Container(
            width: 264,
            height: 264,
            decoration: BoxDecoration(
              border: Border.all(color: Colors.cyanAccent, width: 2.5),
              borderRadius: BorderRadius.circular(22),
            ),
          ),

          // 4. Instructions and Manual Paste button at bottom
          Positioned(
            bottom: 40,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  decoration: BoxDecoration(
                    color: Colors.black87,
                    borderRadius: BorderRadius.circular(20),
                  ),
                  child: const Text(
                    'Point camera at contact\'s QR code',
                    style: TextStyle(color: Colors.white, fontSize: 14),
                  ),
                ),
                const SizedBox(height: 16),
                OutlinedButton.icon(
                  key: const Key('scanner_paste_button'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: Colors.white,
                    side: const BorderSide(color: Colors.white60),
                    backgroundColor: Colors.black45,
                  ),
                  icon: const Icon(Icons.paste, size: 18),
                  label: const Text('Or Paste Code Manually'),
                  onPressed: _showPasteFallbackDialog,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
