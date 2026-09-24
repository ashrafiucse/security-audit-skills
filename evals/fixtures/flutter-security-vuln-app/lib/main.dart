import 'dart:io';
import 'package:flutter/material.dart';
import 'storage.dart';
import 'network.dart';
import 'webview.dart';
import 'deep_link.dart';
import 'channel.dart';

// Global override: every HttpClient in the app accepts any certificate.
class InsecureOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback =
          (X509Certificate cert, String host, int port) => true;
  }
}

void main() {
  HttpOverrides.global = InsecureOverrides();
  runApp(const ShopApp());
}

class ShopApp extends StatelessWidget {
  const ShopApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'flutter_shop',
      onGenerateRoute: (settings) => null,
      home: const HomeScreen(),
    );
  }
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> build(BuildContext context) {
    final api = ApiClient();
    final session = SessionStore();
    return Scaffold(
      appBar: AppBar(title: const Text('flutter_shop')),
      body: Column(
        children: [
          FutureBuilder(
            future: api.fetchDeals(),
            builder: (context, snapshot) => const Text('deals'),
          ),
          ElevatedButton(
            onPressed: () => DeepLinkHandler().handle(context, 'fluttershop://item/42'),
            child: const Text('open item'),
          ),
          ElevatedButton(
            onPressed: () => NativeBridge().syncCart('cart-42'),
            child: const Text('sync cart'),
          ),
          ElevatedButton(
            onPressed: () => session.persistTokens('access-abc', 'refresh-xyz'),
            child: const Text('login'),
          ),
        ],
      ),
    );
  }
}
