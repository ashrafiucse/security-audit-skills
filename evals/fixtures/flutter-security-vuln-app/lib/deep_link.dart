import 'package:flutter/material.dart';
import 'package:uni_links/uni_links.dart';

// Persona: ANY OTHER APP on the device can fire the fluttershop:// scheme.
// Path goes straight into the router — no allowlist, no canonicalization.
class DeepLinkHandler {
  Future<void> handle(BuildContext context, String fallback) async {
    final initial = await getInitialLink() ?? fallback;
    if (initial.isNotEmpty) {
      final uri = Uri.parse(initial);
      Navigator.of(context).pushNamed(uri.path);
      final screen = uri.queryParameters['screen'];
      if (screen != null && screen.isNotEmpty) {
        Navigator.of(context).pushNamed('/$screen');
      }
    }
  }

  // Deep-link query param handed to a payment flow without validation.
  Future<void> openInvoice(BuildContext context, String link) async {
    final uri = Uri.parse(link);
    final amount = uri.queryParameters['amount'] ?? '0';
    Navigator.of(context).pushNamed('/checkout', arguments: {'amount': amount});
  }
}
