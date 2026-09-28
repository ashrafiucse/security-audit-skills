# flutter-security-vuln-app — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Auth/refresh tokens in SharedPreferences (plaintext XML, no Keychain/Keystore) | storage.dart:11,28 | High |
| 2 | Tokens written to plaintext file in app documents dir | storage.dart:17 | High |
| 3 | Token column persisted in unencrypted sqflite DB | storage.dart:24 | High |
| 4 | Global certificate-validation bypass — `HttpOverrides.global` + `badCertificateCallback => true` disables TLS trust for EVERY HttpClient in the app | main.dart:14,20 | Critical |
| 5 | Per-client Dio certificate bypass (`badCertificateCallback` via adapter `onHttpClientCreate`) | network.dart:50 | Critical |
| 6 | Cleartext `http://` API base URL (MITM) | network.dart:9,12 | Medium |
| 7 | Hardcoded payment API key in Dart source (also a `secrets-detection` pattern hit — CI-asserted `sk_(live\|test)` plant) | network.dart:6,19 | Critical |
| 8 | Auth header leaked to logs unconditionally in release path | network.dart:27 | Medium |
| 9 | WebView: unrestricted JS + `AppBridge` JavaScriptChannel + external URL → third-party page reaches Dart `pay:` handler | webview.dart:22-27 | Critical |
| 10 | Deep-link path/query pushed straight into router — route injection from any other app on the device | deep_link.dart:11,14 | High |
| 11 | Deep-link `amount` query param fed into checkout flow unvalidated | deep_link.dart:22-23 | High |
| 12 | Platform channel: external deep-link string used as METHOD NAME (`invokeMethod(action)`) — native side executes attacker-chosen method | channel.dart:16 | High |
| 13 | Platform channel inbound: `call.arguments['path']` forwarded to `writeFile` with no shape validation | channel.dart:22-25 | High |
| 14 | Secrets committed in build script `--dart-define` flags | scripts/build_prod.sh:6-7 | High |
| 15 | Password-reset token from non-CSPRNG `Random()` — guessable tokens | crypto_util.dart:9 | High |
| 16 | Password hashing with md5 | crypto_util.dart:16 | Critical |
| 17 | sha1 for account ticket hashing | crypto_util.dart:20 | High |

## Must NOT trigger (near-misses — safe_counterexamples.dart)

- `encryptedSharedPreferences: true` (safe_counterexamples.dart:16) — SUBSTRING TRAP: the flutter_secure_storage ANDROID OPTION contains the token `SharedPreferences`; only `SharedPreferences.getInstance` call sites are findings
- `String.fromEnvironment('API_KEY')` — the env READER is not the leak; the leak is the committed `--dart-define` value (row 14)
- `Random.secure()` + sha256 counterparts — correct primitives
- `https://api.example-fake.com` (safe API baseUrl) — TLS intact
- `JavascriptMode.disabled` help WebView — no bridge surface
- Route allowlist map lookup (`routeAllowlist[segment]`) — external input never reaches the router directly
- Method allowlist + regex shape check before `invokeMethod('syncCart', ...)` — validated both name and args
- pubspec.yaml `shared_preferences` dependency presence alone — non-sensitive prefs (theme/locale) are legitimate; the finding is WHAT is stored (row 1), not the package

## Out of ground truth (informational)

- Live OSV results on pubspec deps (fixture deliberately unpinned — network-dependent)
- Certificate-pinning ABSENCE on the main Dio client (defense-in-depth note, not a planted finding)
- Release obfuscation/symbol stripping absence (build-hardening note only)
