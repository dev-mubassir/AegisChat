/// Service defining privacy-preserving generic notification content.
///
/// Under the SecureChat security rules, push and local notifications must NEVER contain
/// plaintext message content, sender details, or previews.
class NotificationService {
  static const String genericTitle = 'SecureChat';
  static const String genericBody = 'New encrypted message';

  /// Returns privacy-compliant generic notification payload.
  static Map<String, String> getGenericNotificationPayload() {
    return {
      'title': genericTitle,
      'body': genericBody,
    };
  }
}
