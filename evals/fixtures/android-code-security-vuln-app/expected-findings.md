# android-code-security-vuln-app — Expected findings

Mixed Kotlin/Java fixture: core classes in Kotlin, legacy twins in Java (same bugs, both syntax shapes).

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Tokens in plaintext SharedPreferences (Kotlin) | Storage.kt:11 | High |
| 2 | Tokens written to plaintext file in filesDir | Storage.kt:18 | High |
| 3 | Token column written via string-built INSERT (unencrypted SQLite) | Storage.kt:26 | High |
| 4 | Local SQLi — deeplink-controlled `name` interpolated into SELECT | Storage.kt:32 | High |
| 5 | X509TrustManager with empty `checkServerTrusted` wired into OkHttp (Kotlin) — TLS trust killed for the client | Api.kt:20 | Critical |
| 6 | `HostnameVerifier { _, _ -> true }` (Kotlin) | Api.kt:24 | Critical |
| 7 | Cleartext `http://` BASE_URL (Kotlin) | Api.kt:12 | Medium |
| 8 | Auth token logged to logcat via `Log.d` | Api.kt:40 | Medium |
| 9 | WebView: `addJavascriptInterface` + `@JavascriptInterface pay()/readFile()` + `loadUrl(url)` from intent — third-party page reaches payment and file reads | BillingWeb.kt:11-12,16,21 | Critical |
| 10 | Deep-link component injection — `getStringExtra` → `Class.forName` → `startActivity` (any app instantiates any in-app class) | MainActivity.kt:16-18 | High |
| 11 | PendingIntent with flags=0 (mutable — hijackable on older versions) | MainActivity.kt:25 | High |
| 12 | Hardcoded AES key via `SecretKeySpec` (extractable from APK, never rotatable) | Crypto.kt:15 | Critical |
| 13 | `Cipher.getInstance("AES")` = AES/ECB default | Crypto.kt:20 | High |
| 14 | MD5 for device fingerprint | Crypto.kt:26 | Medium |
| 15 | SHA-1 for legacy ticket | Crypto.kt:31 | Medium |
| 16 | `SecureRandom().setSeed(constant)` — predictable OTP/token source | Crypto.kt:37 | High |
| 17 | X509TrustManager empty checks (Java anonymous-class twin) | LegacyApi.java:23 | Critical |
| 18 | HostnameVerifier anonymous `verify → return true` (Java twin) | LegacyApi.java:28-30 | Critical |
| 19 | Cleartext `http://` BASE_URL (Java twin) | LegacyApi.java:18 | Medium |
| 20 | Legacy token in plaintext SharedPreferences (Java twin) | LegacyStorage.java:11 | High |
| 21 | Legacy local SQLi — concatenated INSERT + SELECT (Java twin) | LegacyStorage.java:19,23 | High |
| 22 | Committed google-services.json API key — check Firebase key restrictions before rating beyond Medium | google-services.json:17 | Medium |

## Must NOT trigger (near-misses — SafeExamples.kt / SafeLegacyExamples.java)

- `EncryptedSharedPreferences.create(...)` + `MasterKey` — the secure storage counterparts (rows 1, 3, 20)
- `execSQL("INSERT ... VALUES (?)", arrayOf(token))` / `rawQuery("... = ?", selectionArgs)` — bound args, the safe twin of rows 4, 21 (note: the SQL string contains `(token)` — a paren INSIDE the literal; the vuln greps key on `$`/`+` interpolation, not parens)
- `CertificatePinner` + default trust — no custom TrustManager exists in the safe files (rows 5, 6, 17, 18 counterparts)
- `https://` constants (rows 7, 19 counterparts)
- `if (BuildConfig.DEBUG) Log.d(TAG, msg)` — gated logging, no token value (row 8 counterpart)
- `webView.loadUrl("https://help...")` constant + JS disabled (row 9 counterpart — `loadUrl(` with a constant is safe; the vuln shape is a variable)
- Route allowlist map + `intent.data.lastPathSegment` (row 10 counterpart — no `getStringExtra`)
- `PendingIntent.getActivity(..., PendingIntent.FLAG_IMMUTABLE)` (row 11 counterpart — same call, flags differ)
- AndroidKeyStore `KeyGenParameterSpec` + `AES/GCM/NoPadding` + SHA-256 + `SecureRandom()` unseeded (rows 12-16 counterparts)
- `MODE_PRIVATE` by itself — the flag is fine; the store class is the finding
- `.sslSocketFactory(ssl.socketFactory, trustAllCerts)` wiring line — evidence supporting rows 5/17, not a standalone finding
- build.gradle `minifyEnabled false` — informational build-hardening note only

## Out of ground truth (informational)

- Live OSV results on gradle deps (network-dependent)
- FLAG_SECURE absence on auth/payment screens (defense-in-depth note)
- Manifest-side rows (exported components etc.) — owned by `mobile-security`, not planted here
