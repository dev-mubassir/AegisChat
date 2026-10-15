import 'package:app/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('SecureChatApp smoke test', (WidgetTester tester) async {
    await tester.pumpWidget(const MyApp());
    expect(find.text('SecureChat'), findsOneWidget);
    expect(find.text('SecureChat Ready'), findsOneWidget);
  });
}
