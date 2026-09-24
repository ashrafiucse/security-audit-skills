# Security Audit — flutter_shop fixture

Scope: `/tmp/sas-flutter/evals/fixtures/flutter-security-vuln-app` (read-only).
Method: `skills/flutter-security/SKILL.md` steps 0–8 executed in order with census discipline; `skills/secrets-detection/SKILL.md` patterns applied for hardcoded keys. `expected-findings.md` was excluded from every scan (`--glob '!**/expected-findings.md'`) and never opened.

## Stack summary

- **App**: `flutter_shop` — Flutter/Dart mobile app (fixture; fake data only, planted vulns treated as real per audit instructions).
- **Files**: `pubspec.yaml`, `scripts/build_prod.sh`, 8 Dart files under `lib/` (`main`, `storage`, `network`, `webview`, `deep_link`, `channel`, `crypto_util`, `safe_counterexamples`).
- **Key deps** (pubspec.yaml:8–18): `shared_preferences ^2.0.0`, `sqflite ^2.0.0`, `dio ^5.0.0`, `webview_flutter ^4.0.0`, `uni_links ^0.5.0`, `crypto ^3.0.0`, `path_provider ^2.0.0`. **`flutter_secure_storage` is NOT a dependency** (it appears only as the safe counterexample in `lib/safe_counterexamples.dart:3`, which would not resolve against this pubspec).
- **Step 0 detection record**: secure-storage package absent; dio + http in use; WebView in use; uni_links deep links in use; platform channels present (`MethodChannel('fluttershop/bridge')`, lib/channel.dart:6); no obfuscated release build; no `pubspec.lock`; no `.git` (snapshot fixture — history checks N/A); no Android/iOS platform folders.

Severity counts: **5 Critical, 7 High, 1 Medium, 3 Low** (16 findings).

---

### SEC-001 — Auth tokens persisted in plaintext SharedPreferences, plaintext file, and unencrypted sqflite
- **Severity**: Critical
- **Where**: lib/storage.dart:11–13 (SharedPreferences), lib/storage.dart:16–17 (`tokens.txt` in app-documents dir), lib/storage.dart:19–24 (`shop.db` sqlite insert); sink invoked at lib/main.dart:61.
- **Evidence**:
  ```dart
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('access_token', accessToken);
  await prefs.setString('refresh_token', refreshToken);
  ...
  final tokenFile = File('${docs.path}/tokens.txt');
  await tokenFile.writeAsString('access=$accessToken\nrefresh=$refreshToken');
  ...
  final db = await openDatabase('shop.db', version: 1, ...);
  await db.insert('session', {'token': accessToken});
  ```
- **Abuse story**: Device thief / rooted-device app / backup extractor reads the session. SharedPreferences is a plaintext XML file, app-documents files are plain on disk, and sqflite is an unencrypted sqlite DB — any of the three yields the access **and** refresh token, giving full account takeover without re-authentication. Three redundant insecure copies of the same credential.
- **Fix**: Store tokens only in `const FlutterSecureStorage(aOptions: AndroidOptions(encryptedSharedPreferences: true), iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock))` (the shape shown in lib/safe_counterexamples.dart:12–15); delete the file and DB copies; purge existing plaintext rows/files on migration.

### SEC-002 — Global TLS-validation kill switch via `HttpOverrides.global`
- **Severity**: Critical
- **Where**: lib/main.dart:10–16 (class + `badCertificateCallback ... => true`), lib/main.dart:20 (`HttpOverrides.global = InsecureOverrides();`).
- **Evidence**:
  ```dart
  class InsecureOverrides extends HttpOverrides {
    @override
    HttpClient createHttpClient(SecurityContext? context) {
      return super.createHttpClient(context)
        ..badCertificateCallback =
            (X509Certificate cert, String host, int port) => true;
    }
  }
  ...
  HttpOverrides.global = InsecureOverrides();
  ```
- **Abuse story**: Every `HttpClient` in the app — including ones created by libraries the developer never audited — now accepts any certificate. An attacker on the same coffee-shop Wi-Fi MITMs the connection and harvests the `Authorization` header (SEC-004 key / bearer tokens) in transit.
- **Fix**: Delete the override entirely; there is no safe production shape for a global `=> true` callback. If a specific host has a legitimately self-signed cert, pin that host's CA/fingerprint in that one client.

### SEC-003 — Per-client Dio certificate bypass via `onHttpClientCreate`
- **Severity**: Critical
- **Where**: lib/network.dart:44–52 (adapter wiring at 48, `badCertificateCallback => true` at 50), inside `legacyFetch(String path)` (lib/network.dart:40).
- **Evidence**:
  ```dart
  (insecure.httpClientAdapter as DefaultHttpClientAdapter).onHttpClientCreate =
      (client) {
    client.badCertificateCallback = (cert, host, port) => true;
    return client;
  };
  final resp = await insecure.get(path);
  ```
- **Abuse story**: Independent of SEC-002, this Dio client accepts any invalid certificate for any host it talks to (same `http://` API host as SEC-006). MITM position → full request/response interception for everything fetched through `legacyFetch`. "Dev shortcut that shipped" — it is public, shipped code.
- **Fix**: Remove the `onHttpClientCreate` callback (Dio validates TLS by default). For test hosts, use an environment-gated dev flavor, never shipped code.

### SEC-004 — Hardcoded Stripe-format secret key in Dart source
- **Severity**: Critical
- **Where**: lib/network.dart:6 (literal), used at lib/network.dart:19 (`Authorization: Bearer $apiKey`).
- **Evidence**:
  ```dart
  static const String apiKey = 'AKIAIOSFODNN7EXAMPLE';
  ...
  options.headers['Authorization'] = 'Bearer $apiKey';
  ```
- **Abuse story**: `sk_test_` is the live Stripe **test-mode secret key** format with realistic entropy. Anyone with the binary (APK strings, decompile) or repo access extracts the key and can make API calls that succeed against the live API in test mode — and the same `Authorization` header shape means swapping to a production key is one edit away. Secrets-detection class: hardcoded key, correct prefix + committed literal (fixture note: value is fake per audit rules, still reported as a real planted leak).
- **Fix**: Rotate/revoke the key (removal is not revocation). Fetch keys server-side; the client should never hold a `sk_`-class secret. If a public client-side key is unavoidable, use the designated publishable-key class. See also SEC-005 (same value committed in the build script).

### SEC-005 — Secrets committed as `--dart-define` flags in the production build script
- **Severity**: High
- **Where**: scripts/build_prod.sh:6 (`API_KEY`), scripts/build_prod.sh:7 (`AMPLITUDE_KEY`).
- **Evidence**:
  ```bash
  flutter build apk --release \
    --dart-define=API_KEY=AKIAIOSFODNN7EXAMPLE \
    --dart-define=AMPLITUDE_KEY=amplitude-fake-000111 \
  ```
- **Abuse story**: `--dart-define` values are baked into the release binary and are trivially extractable from the APK (the Dart-side `String.fromEnvironment` reader — lib/safe_counterexamples.dart:109–111 — is fine; the committed value is the leak). Anyone with the APK or the script recovers the payment key (same key as SEC-004) plus the analytics key. The `AMPLITUDE_KEY` value is placeholder-grade entropy (`amplitude-fake-000111`) but the committed-flag pattern is the finding.
- **Fix**: Remove values from the script; inject at build time from the CI secret store (`$API_KEY`), rotate both keys.

### SEC-006 — Cleartext `http://` API endpoints on a client that sends the auth header
- **Severity**: Critical
- **Where**: lib/network.dart:9 (`baseUrl` constant), lib/network.dart:12 (Dio `BaseOptions` baseUrl), auth header attached at lib/network.dart:18–20; same constant reused by `legacyFetch` (lib/network.dart:44).
- **Evidence**:
  ```dart
  final String baseUrl = 'http://api.example-fake.com/v1';
  final dio = Dio(BaseOptions(baseUrl: 'http://api.example-fake.com/v1', ...));
  ...
  options.headers['Authorization'] = 'Bearer $apiKey';
  ```
- **Abuse story**: Every API request — including `/deals` (lib/network.dart:31) and anything via `legacyFetch` — travels in cleartext **while carrying the `Authorization` bearer header**. A passive network observer (no TLS to break) reads the API key and any session data; an active attacker rewrites responses. Skill grading: `http://` carrying the auth header is Critical. (No `http://localhost` safe near-miss exists in this fixture; both hits are the remote API.)
- **Fix**: Switch to `https://` endpoints; enforce via a lint/build check that rejects `http://` non-localhost constants; on Android also set `usesCleartextTraffic="false"`.

### SEC-007 — WebView JavaScript bridge exposed to an external URL (payment handler, no origin check)
- **Severity**: High
- **Where**: lib/webview.dart:22 (`JavascriptMode.unrestricted`), lib/webview.dart:23 (`addJavaScriptChannel('AppBridge', ...)`), lib/webview.dart:27 (`loadRequest(Uri.parse(widget.targetUrl))` — attacker-influenced widget param, not a constant), handler at lib/webview.dart:30–34.
- **Evidence**:
  ```dart
  ..setJavaScriptMode(JavascriptMode.unrestricted)
  ..addJavaScriptChannel('AppBridge', onMessageReceived: (msg) {
    handleBridge(msg.toJavaScriptChannelName(), msg.body as String);
  })
  ..loadRequest(Uri.parse(widget.targetUrl));
  ...
  if (body.startsWith('pay:')) {
    NativeBridgeProxy.pay(body.substring(4));
  }
  ```
- **Abuse story**: The page loaded in this WebView gets a full Dart API (`AppBridge`) with **no origin check** — the file's own comment confirms the web content is third-party marketing pulled from an external URL. If `targetUrl` is influenced by a deep link / promo link (it is a plain constructor parameter, and this app has an unvalidated deep-link path, SEC-010), an attacker loads their own page, call `AppBridge.postMessage('pay:...')`, and drive the payment handler with a payload of their choice. Unrestricted JS + external URL + bridge = the classic chain.
- **Fix**: Load only a const/allowlisted origin, add a `NavigationDelegate` that blocks off-origin navigations, and never register a payment-capable channel on external content. Validate bridge message shape (e.g. strict JSON schema) before dispatching.

### SEC-008 — Deep-link string used as the native method name (`invokeMethod(action)`)
- **Severity**: High
- **Where**: lib/channel.dart:15–17 (`handleDeepLinkAction` → `invokeMethod(action)` at line 16).
- **Evidence**:
  ```dart
  Future<void> handleDeepLinkAction(String action) async {
    // action traces to an external app's link — native side executes it
    await _channel.invokeMethod(action);
  }
  ```
- **Abuse story**: Any other app on the device fires the `fluttershop://` scheme (see SEC-010); the action string flows verbatim as the **native method name** on channel `fluttershop/bridge`. The attacker's link chooses which native method runs — whatever the Kotlin/Swift side exposes (file writes, payments, session ops) becomes callable by a malicious app.
- **Fix**: Const allowlist of method names (`{'syncCart', 'refreshSession'}` per lib/safe_counterexamples.dart:100–101) checked before invoke; never pass externally-derived strings as method names.

### SEC-009 — Inbound platform-channel arguments used unvalidated and forwarded to native file write
- **Severity**: High
- **Where**: lib/channel.dart:22–26 (`setMethodCallHandler`, `call.arguments['path']` at 24, forwarded to `writeFile` at 25).
- **Evidence**:
  ```dart
  _channel.setMethodCallHandler((call) async {
    if (call.method == 'exportLog') {
      final target = call.arguments['path'] as String;
      await _channel.invokeMethod('writeFile', {'dest': target});
    }
    ...
  ```
- **Abuse story**: The native side (or any plugin/broadcast path reaching this channel) sends `exportLog` with `path` — Dart casts and forwards it to native `writeFile` with zero shape validation. A path like `../../sdcard/...` or an app-private path makes the app write attacker-chosen data to attacker-chosen locations; the native side trusts the plugin. Trust boundary violated in the inbound direction.
- **Fix**: Validate shape before forwarding (regex-constrain `path` to a const export directory + safe filename charset, as the safe counterpart does for `cartRef` at lib/safe_counterexamples.dart:103–107); reject anything else.

### SEC-010 — Deep-link path and query parameter injected straight into the router (no allowlist)
- **Severity**: High
- **Where**: lib/deep_link.dart:8 (`getInitialLink()`), lib/deep_link.dart:11 (`pushNamed(uri.path)`), lib/deep_link.dart:13–15 (`?screen=` query → `pushNamed('/$screen')`).
- **Evidence**:
  ```dart
  final initial = await getInitialLink() ?? fallback;
  ...
  final uri = Uri.parse(initial);
  Navigator.of(context).pushNamed(uri.path);
  final screen = uri.queryParameters['screen'];
  if (screen != null && screen.isNotEmpty) {
    Navigator.of(context).pushNamed('/$screen');
  }
  ```
- **Abuse story**: Any other app on the device can fire the scheme (`uni_links`, and `main.dart:59` drives this handler). Both the link **path** and the `screen` query param flow into `pushNamed` with no allowlist or canonicalization — classic route injection: the attacker opens private screens (`/admin`, `/wallet`) by name, or names that resolve with attacker-chosen state.
- **Fix**: Canonicalize, then map through a const allowlist (the shape at lib/safe_counterexamples.dart:77–83): resolve deep-link segments to fixed route names and drop everything unmapped.

### SEC-011 — Deep-link `amount` query parameter fed to the checkout flow unvalidated
- **Severity**: High
- **Where**: lib/deep_link.dart:20–24 (`openInvoice`, amount read at 22, pushed as checkout `arguments` at 23).
- **Evidence**:
  ```dart
  final amount = uri.queryParameters['amount'] ?? '0';
  Navigator.of(context).pushNamed('/checkout', arguments: {'amount': amount});
  ```
- **Abuse story**: The attacker crafts `fluttershop://invoice?amount=<x>` and gets the user to tap it; the checkout screen receives an attacker-controlled `amount` as route configuration (treated as input-as-config). Price manipulation / social-engineered purchases at a chosen amount; also a second route-injection sink distinct from SEC-010.
- **Fix**: Treat query params as hostile data, not config — re-fetch the authoritative amount server-side by invoice id, or validate against a strict numeric range before it may influence a payment screen.

### SEC-012 — Password-reset tokens generated with non-CSPRNG `Random()`
- **Severity**: High
- **Where**: lib/crypto_util.dart:8–12 (`Random()` at 9).
- **Evidence**:
  ```dart
  final randomGen = Random();
  final bytes = List<int>.generate(16, (_) => randomGen.nextInt(256));
  return base64Url.encode(bytes);
  ```
- **Abuse story**: `dart:math` `Random()` is seeded predictably and is not cryptographically secure. The value it protects is a **password reset token** — an attacker who models the generator can predict issued tokens and reset other users' passwords (account takeover). 16 bytes of non-CSPRNG entropy is not 16 bytes of security.
- **Fix**: `Random.secure()` with ≥32 bytes (the safe counterpart, lib/safe_counterexamples.dart:38–42).

### SEC-013 — Passwords hashed with MD5
- **Severity**: Critical
- **Where**: lib/crypto_util.dart:14–17 (`hashPassword`, `md5.convert` at 16).
- **Evidence**:
  ```dart
  String hashPassword(String password) {
    return md5.convert(utf8.encode(password)).toString();
  }
  ```
- **Abuse story**: Unsalted MD5 for passwords: fast (GPU-crackable), collision-broken, rainbow-tableable. Any DB/backup leak (see SEC-001's unencrypted sqlite) converts stored hashes back to plaintext nearly instantly for most human passwords.
- **Fix**: Don't hash passwords client-side at all — send over TLS to a server that uses argon2/bcrypt/scrypt (as lib/safe_counterexamples.dart:35–36 notes). If a local PIN check is unavoidable, use a salted slow KDF.

### SEC-014 — Ungated `print` of outgoing headers (release-build log leakage)
- **Severity**: Medium
- **Where**: lib/network.dart:24–27 (`logOutgoing`, `print('outgoing: $headers')` at 27).
- **Evidence**:
  ```dart
  // Release-build leakage: interceptor logs the auth header unconditionally.
  void logOutgoing(Object headers) {
    print('outgoing: $headers');
  }
  ```
- **Abuse story**: On Android, `print`/`debugPrint` output goes to logcat, readable by adb (and on older/rooted devices by other apps). If wired to log request headers — the doc comment says exactly that intent — the `Authorization: Bearer ...` value lands in system logs in release builds. Note: no caller exists in the fixture today (verified by grep), so it is one refactor from leaking; severity Medium for the ungated sink in non-dev code.
- **Fix**: Wrap in `if (kDebugMode)` at minimum; better, a structured logger that redacts `Authorization`/token fields by default.

### SEC-015 — Unsalted SHA-1 "ticket" derived from a guessable account id
- **Severity**: Low
- **Where**: lib/crypto_util.dart:19–21 (`legacyTicket`, `sha1.convert` at 20).
- **Evidence**:
  ```dart
  String legacyTicket(String accountId) {
    return sha1.convert(utf8.encode(accountId)).toString();
  }
  ```
- **Abuse story**: `sha1(accountId)` with no secret/salt is forgeable by anyone who knows (or enumerates) account ids — if this ticket is accepted as proof of anything, it proves nothing. Severity held at Low because SHA-1 itself on non-password data is graded verified-safe by the skill and no consumer of the ticket exists in the fixture to confirm exploitability.
- **Fix**: If the ticket must assert authenticity, use an HMAC with a server-held secret (or server-issued short-lived tokens); otherwise delete it.

### SEC-016 — Release build ships without obfuscation (`--obfuscate --split-debug-info` absent)
- **Severity**: Low (hardening / informational)
- **Where**: scripts/build_prod.sh:5–8.
- **Evidence**:
  ```bash
  flutter build apk --release \
    --dart-define=... \
    --split-per-abi
  ```
- **Abuse story**: Un-obfuscated release binaries keep Dart symbol names, making the extraction of the hardcoded key (SEC-004/005) and reverse-engineering of the bridge/channel logic materially easier. Not a vuln by itself; an amplifier.
- **Fix**: `flutter build apk --release --obfuscate --split-debug-info=out/symbols`.

### SEC-017 — Unpinned dependencies; no `pubspec.lock`
- **Severity**: Low
- **Where**: pubspec.yaml:10–18 (caret ranges, no lockfile in repo — verified by file listing).
- **Evidence**: `shared_preferences: ^2.0.0`, `dio: ^5.0.0`, `webview_flutter: ^4.0.0`, `uni_links: ^0.5.0`, etc.; `find` shows no `pubspec.lock`.
- **Abuse story**: Builds are not reproducible — a supply-chain compromise or breaking/malicious transitive bump can silently enter a release build. Dependency CVE scanning (osv_scan over pubspec.lock) is also impossible without the lockfile.
- **Fix**: Commit `pubspec.lock` for apps; run `dart pub outdated`/OSV scan in CI (see `../dependency-vulns/SKILL.md`).

---

## Census receipts

Every census scan ran with `--glob '!**/expected-findings.md'`; `expected-findings.md` was never read by any command.

| # | Skill step / scan | Patterns | Hits | Dispositioned | Resulting findings |
|---|---|---|---|---|---|
| 1 | Step 1 — storage census | `SharedPreferences.getInstance` / `writeAsString(` / `openDatabase(\|db.insert(\|db.execute(` | 6 | 6 | SEC-001 (all credential-class: tokens in prefs, file, sqlite; none theme/locale/flags) |
| 2 | Step 2 — cert & cleartext | `badCertificateCallback\|onBadCertificate` / `HttpOverrides` / `onHttpClientCreate` / `http://` | 7 | 7 | SEC-002 (global override), SEC-003 (per-client Dio), SEC-006 (cleartext + auth header). Safe-counterexample https hits: none for cert patterns. No `http://localhost` near-miss present. |
| 3 | Step 3 — WebView | `JavascriptMode.unrestricted\|setJavaScriptMode` / `addJavaScriptChannel(` / `loadRequest(\|loadHtmlString(\|loadUrl(` | 5 | 5 | SEC-007 (vuln: unrestricted + channel + external URL). Verified-safe: lib/safe_counterexamples.dart:68–69 (JS disabled, const https URL, no channel). |
| 4 | Step 4 — platform channels | `invokeMethod(` / `setMethodCallHandler(` / `call.arguments` | 6 | 6 | SEC-008 (`invokeMethod(action)`), SEC-009 (unvalidated `call.arguments['path']`). Verified-safe: channel.dart:11 (const name + map arg), safe_counterexamples.dart:95 (allowlist + regex). |
| 5 | Step 5 — deep links | `getInitialLink\|linkStream\|appLinks` / `pushNamed(` | 4 | 4 | SEC-010 (path + `screen` → router), SEC-011 (`amount` → checkout). Verified-safe: safe_counterexamples.dart:80–84 allowlist map (resolve(), not pushNamed). |
| 6 | Step 6 — secrets in build/source | `dart-define` / key-ish terms in `*.dart` / `print(\|debugPrint(` | 21 | 21 | SEC-004 (hardcoded sk_test_ key; found via secrets scan since Step-6 filter drops `test` lines), SEC-005 (committed dart-defines), SEC-014 (ungated print). Dispositions: 11 storage/network token-handling lines → SEC-001/006 context; 5 crypto_util comment/code lines → SEC-012/013; 1 FP — safe_counterexamples.dart:49 is the substring `fingerprint(`, not a print call. |
| 7 | Step 7 — crypto | `Random()` / `md5.\|sha1.` | 3 | 3 | SEC-012 (Random() reset token), SEC-013 (md5 password), SEC-015 (sha1 ticket, graded Low). `Random.secure()` in safe file does not match `Random()`. |
| 8 | Step 8 — build hygiene | `flutter build` | 1 | 1 | SEC-016 (no `--obfuscate --split-debug-info`) |
| 9 | secrets-detection — literal patterns (sk_/AKIA/ghp_/xox/AIza/Bearer/private-key) | project-wide | 3 | 3 | SEC-004 (`sk_test_...` in network.dart:6), SEC-005 (sk_test_ + amplitude key in build_prod.sh:6–7). Entropy triage: sk_test_ value realistic; amplitude value placeholder-grade (pattern still flagged). No private keys, no Basic-auth blobs. |
| 10 | secrets-detection — hygiene/dev artifacts | `.env` tracked / `.gitignore` / `.vscode\|.idea\|postman\|*.http\|devcontainer` / git history | 0 | 0 (N/A) | No `.git` in fixture (snapshot) → history checks not applicable; no dev-artifact files; no .env; no .gitignore. |

Totals: 56 hits across 10 census scans, 56 dispositioned, 0 un-dispositioned hits, 0 hits in `expected-findings.md` (excluded everywhere).

## Not assessed

- **Android/iOS platform manifests** — no `android/` or `ios/` directories in the fixture; the mobile-security half (exported components, `usesCleartextTraffic`, iOS ATS, backup flags, deep-link intent-filter registration) could not be checked.
- **Native side of `MethodChannel('fluttershop/bridge')`** (lib/channel.dart:6) — Kotlin/Swift handlers absent from the fixture; SEC-008/009 impact on the native side is inferred from the Dart-side shapes.
- **Dependency CVEs** — no `pubspec.lock` exists, so osv/dependency scanning has no manifest to parse (covered instead by SEC-017).
- **Git history / gitleaks / trufflehog** — no `.git` directory; history checks N/A.
- **Server-side behavior** (checkout amount validation, ticket acceptance) — out of reach of this repo.
- **Runtime verification** — app was not built or executed (read-only static audit).
- **`validateStatus: (status) => status < 500`** (lib/network.dart:13) — accepts 4xx as non-error; robustness issue, outside both skills' finding shapes, noted here only.
- **Call-path reachability** — `legacyFetch`, `openInvoice`, `registerHandlers`, `handleDeepLinkAction`, `logOutgoing`, `CryptoUtil` methods, and `PromoWebScreen` are not referenced from `main.dart`'s HomeScreen; they are public shipped library code and are reported on their shape per audit rules (reachability noted per finding).
