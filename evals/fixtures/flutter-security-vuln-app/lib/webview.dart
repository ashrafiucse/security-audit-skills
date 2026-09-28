import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

// Persona: the web content is THIRD-PARTY (marketing pages pulled from an
// external URL). JS bridge + external origin = the page can call into Dart.
class PromoWebScreen extends StatefulWidget {
  const PromoWebScreen({super.key, required this.targetUrl});

  final String targetUrl;

  @override
  State<PromoWebScreen> createState() => _PromoWebScreenState();
}

class _PromoWebScreenState extends State<PromoWebScreen> {
  late final WebViewController controller;

  @override
  void initState() {
    super.initState();
    controller = WebViewController()
      ..setJavaScriptMode(JavascriptMode.unrestricted)
      ..addJavaScriptChannel('AppBridge', onMessageReceived: (msg) {
        // bridge handlers assume messages are trusted — no origin check exists
        handleBridge(msg.toJavaScriptChannelName(), msg.body as String);
      })
      ..loadRequest(Uri.parse(widget.targetUrl));
  }

  void handleBridge(String channel, String body) {
    if (body.startsWith('pay:')) {
      NativeBridgeProxy.pay(body.substring(4));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('promotions')),
      body: WebViewWidget(controller: controller),
    );
  }
}

class NativeBridgeProxy {
  static void pay(String payload) {}
}
