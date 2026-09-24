import 'package:dio/dio.dart';

class ApiClient {
  // Hardcoded payment API key (planted fake — test-format keys in source are
  // still real leaks: they work against the live API in test mode)
  static const String apiKey = 'AKIAIOSFODNN7EXAMPLE';

  // Backend endpoints (fixture — example-fake.com is reserved for docs)
  final String baseUrl = 'http://api.example-fake.com/v1';

  final dio = Dio(BaseOptions(
    baseUrl: 'http://api.example-fake.com/v1',
    validateStatus: (status) => status != null && status < 500,
  ));

  ApiClient() {
    dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) async {
        options.headers['Authorization'] = 'Bearer $apiKey';
        handler.next(options);
      },
    ));
  }

  // Release-build leakage: interceptor logs the auth header unconditionally.
  void logOutgoing(Object headers) {
    print('outgoing: $headers');
  }

  Future<dynamic> fetchDeals() async {
    final resp = await dio.get('/deals');
    return resp.data;
  }

  // Dev shortcut that shipped: this client accepts ANY invalid certificate,
  // including for pinned hosts (separate class from the global override in
  // main.dart — per-client Dio shape).
  Future<dynamic> legacyFetch(String path) async {
    final legacy = Dio(BaseOptions(baseUrl: baseUrl))
      ..interceptors.add(InterceptorsWrapper(
        onError: (e, h) async {
          final bad = e.error as dynamic;
          h.rejectError(e);
        },
      ));
    legacy.httpClientAdapter; // dio >=5: adapter-level validation lives here
    final insecure = Dio(BaseOptions(baseUrl: baseUrl));
    (insecure.httpClientAdapter as DefaultHttpClientAdapter).onHttpClientCreate =
        (client) {
      client.badCertificateCallback = (cert, host, port) => true;
      return client;
    };
    final resp = await insecure.get(path);
    return resp.data;
  }
}
