import 'dart:math';
import 'dart:convert';
import 'package:crypto/crypto.dart';

class CryptoUtil {
  // Password reset token from a non-CSPRNG: Random() is seeded predictably
  // and is not cryptographically secure — tokens become guessable.
  String generateResetToken() {
    final randomGen = Random();
    final bytes = List<int>.generate(16, (_) => randomGen.nextInt(256));
    return base64Url.encode(bytes);
  }

  // Password hashing with md5: fast, collision-broken, rainbow-tableable.
  String hashPassword(String password) {
    return md5.convert(utf8.encode(password)).toString();
  }

  String legacyTicket(String accountId) {
    return sha1.convert(utf8.encode(accountId)).toString();
  }
}
