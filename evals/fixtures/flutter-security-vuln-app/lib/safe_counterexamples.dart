import 'dart:io';
import 'dart:math';
import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:dio/dio.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:sqflite/sqflite.dart';

// SAFE counterparts for every flutter-security class. The raw vulnerable
// forms must have ZERO literal occurrences in this file (CI-enforced by
// MUST_NOT_MATCH rules in scripts/selftest_patterns.py).

class SafeSessionStore {
  // storage: tokens live in the Keychain/Keystore-backed store
  final storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  Future<void> persistTokens(String accessToken, String refreshToken) async {
    await storage.write(key: 'access_token', value: accessToken);
    await storage.write(key: 'refresh_token', value: refreshToken);
  }

  Future<String?> readAccessToken() => storage.read(key: 'access_token');
}

class SafeApi {
  // network: TLS validated by default; https endpoints only
  static const String baseUrlV2 = 'https://api.example-fake.com/v1';

  final dio = Dio(BaseOptions(baseUrl: baseUrlV2));

  Future<dynamic> fetchDeals() async {
    final resp = await dio.get('/deals');
    return resp.data;
  }
}

class SafeCrypto {
  // crypto: CSPRNG + SHA-256 for non-password use; passwords belong to
  // argon2/bcrypt on the SERVER, never hashed client-side
  String generateResetToken() {
    final rng = Random.secure();
    final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
    return base64Url.encode(bytes);
  }

  String fingerprint(String payload) {
    return sha256.convert(utf8.encode(payload)).toString();
  }
}

class SafeDb {
  // sqflite: schema holds no credential columns; data fetched by row id
  Future<List<Map<String, Object?>>> cartItems(Database db, int userId) async {
    return db.query('cart_items', where: 'user_id = ?', whereArgs: [userId]);
  }
}

// webview: JS disabled for static help content; no JavaScriptChannel is
// registered, so no page can reach Dart-side handlers.
class SafeHelpWebView {
  late final WebViewController controller;

  void init() {
    controller = WebViewController()
      ..setJavaScriptMode(JavascriptMode.disabled)
      ..loadRequest(Uri.parse('https://help.example-fake.com/faq'));
  }
}

// deep links: external input is mapped through an allowlist, never fed
// straight to a router.
class SafeDeepLinkRouter {
  static const Map<String, String> routeAllowlist = {
    'item': '/items',
    'promo': '/promotions',
  };

  String? resolve(Uri uri) {
    final segment = uri.host.isNotEmpty ? uri.host : uri.pathSegments.first;
    return routeAllowlist[segment];
  }
}

// platform channel: method names + argument shapes validated on both sides.
class SafeNativeBridge {
  static const MethodChannel _ch = MethodChannel('fluttershop/bridge');
  static const Set<String> allowedMethods = {'syncCart', 'refreshSession'};

  Future<void> syncCart(String cartRef) async {
    if (!allowedMethods.contains('syncCart')) return;
    if (!RegExp(r'^[A-Za-z0-9-]{1,64}$').hasMatch(cartRef)) return;
    await _ch.invokeMethod('syncCart', {'ref': cartRef});
  }
}

// build: secrets never ride in committed build flags; fetched from the CI
// secret store at build time (reader pattern shown for completeness).
class BuildFlags {
  static const String apiKey =
      String.fromEnvironment('API_KEY'); // value injected by CI, not committed
}
