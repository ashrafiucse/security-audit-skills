import 'dart:io';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite/sqflite.dart';
import 'package:path_provider/path_provider.dart';

// Persona: end-user auth tokens. Device thief, backup extractor, or any
// other app on a rooted device reads these — SharedPreferences is a
// plaintext XML file inside the app data dir, not Keychain/Keystore.
class SessionStore {
  Future<void> persistTokens(String accessToken, String refreshToken) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('access_token', accessToken);
    await prefs.setString('refresh_token', refreshToken);

    final docs = await getApplicationDocumentsDirectory();
    final tokenFile = File('${docs.path}/tokens.txt');
    await tokenFile.writeAsString('access=$accessToken\nrefresh=$refreshToken');

    final db = await openDatabase('shop.db', version: 1,
        onCreate: (db, _) async {
      await db.execute(
          'CREATE TABLE session (id INTEGER PRIMARY KEY, token TEXT)');
    });
    await db.insert('session', {'token': accessToken});
  }

  Future<String?> readAccessToken() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString('access_token');
  }
}
