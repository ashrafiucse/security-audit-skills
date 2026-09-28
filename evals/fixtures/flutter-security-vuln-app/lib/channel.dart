import 'package:flutter/services.dart';

// Platform-channel trust boundary: the Dart side forwards an argument that
// came from a deep link (other-app persona) into native code verbatim, and
// the native handler (Kotlin/Swift side of this repo) trusts it as a
// filename/method name.
class NativeBridge {
  static const MethodChannel _channel = MethodChannel('fluttershop/bridge');

  Future<void> syncCart(String cartRef) async {
    await _channel.invokeMethod('syncCart', {'ref': cartRef});
  }

  Future<void> handleDeepLinkAction(String action) async {
    // action traces to an external app's link — native side executes it
    await _channel.invokeMethod(action);
  }

  // Inbound: native (or a plugin another app can reach) sends args that are
  // used without shape validation.
  void registerHandlers() {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'exportLog') {
        final target = call.arguments['path'] as String;
        await _channel.invokeMethod('writeFile', {'dest': target});
      }
      return null;
    });
  }
}
