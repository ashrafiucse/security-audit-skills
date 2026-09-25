# Security Audit — android-code-security-vuln-app

**Scope:** read-only code audit of the native Android app fixture at
`evals/fixtures/android-code-security-vuln-app`, performed per
`skills/android-code-security/SKILL.md` (Steps 0–8), covering **both Kotlin and Java**.
Blind-eval hygiene: `expected-findings.md` was excluded (`--glob '!**/expected-findings.md'`)
from every recursive scan and was never opened or read. All evidence below cites file:line
content actually read during this audit. Planted-looking/fake values are reported as real
per audit instructions.

Paths are relative to the fixture root. Fixture inventory: 11 files
(`app/build.gradle`, `app/google-services.json`, 9 Kotlin/Java sources under
`app/src/main/java/com/example/shop/`). No `AndroidManifest.xml`, no `res/`, no
`gradle.lockfile`, no test sources exist in the fixture.

## Stack summary

- **Type:** native Android app, `com.android.application` plugin (app/build.gradle:3);
  mixed **Kotlin (6 files) + Java (3 files)** codebase sharing the same bugs as
  Kotlin/Java "twins" (`Api.kt`/`LegacyApi.java`, `Storage.kt`/`LegacyStorage.java`,
  `SafeExamples.kt`/`SafeLegacyExamples.java`).
- **Build:** namespace `com.example.shop`, compileSdk 34, minSdk 24, release
  `minifyEnabled false` (app/build.gradle:8–16). Google Services plugin applied
  (app/build.gradle:4) with `app/google-services.json` committed.
- **Libraries:** OkHttp 4.12.0 (app/build.gradle:22), androidx.security:security-crypto
  **1.1.0-alpha06** (app/build.gradle:23 — EncryptedSharedPreferences/MasterKey available
  but only used in the `Safe*` files, never for the real token stores), androidx.webkit
  1.10.0 (app/build.gradle:24). No Retrofit, no gradle.lockfile.
- **WebView:** present (`BillingWeb.kt`) with a JS bridge (`addJavascriptInterface`).
- **Note:** the codebase ships explicit safe counterparts (`SafeExamples.kt`,
  `SafeLegacyExamples.java`) which were used to calibrate safe dispositions; they are not
  findings.

---

### SEC-001 — Trust-all TLS client in Kotlin: empty X509TrustManager + always-true HostnameVerifier wired into OkHttp

**Severity:** Critical

**Where:**
- `app/src/main/java/com/example/shop/Api.kt:18-21` — `X509TrustManager` with empty `checkClientTrusted`/`checkServerTrusted` bodies
- `app/src/main/java/com/example/shop/Api.kt:24` — always-true `HostnameVerifier`
- `app/src/main/java/com/example/shop/Api.kt:26-32` — wired via `sslSocketFactory(ssl.socketFactory, trustAllCerts)` and `hostnameVerifier(hostnameVerifier)`

**Evidence:**
```kotlin
private val trustAllCerts = object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}
private val hostnameVerifier = HostnameVerifier { _, _ -> true }
...
    return OkHttpClient.Builder()
        .sslSocketFactory(ssl.socketFactory, trustAllCerts)
        .hostnameVerifier(hostnameVerifier)
```

**Abuse story:** A user on hostile Wi-Fi (café/airport) has every HTTPS response replaced by
an attacker: `checkServerTrusted` accepts any certificate chain and the verifier accepts any
hostname, and both are installed on the client returned by `client()`. The attacker's proxy
harvests `authHeader()` (`Bearer $authToken`, Api.kt:35) and can serve tampered API
responses.

**Fix:** Delete the custom trust manager and verifier; use the platform default trust
(`OkHttpClient.Builder()` defaults) and add `CertificatePinner` for the token-carrying host
(safe shape already exists in `SafeExamples.kt:43-50`).

---

### SEC-002 — Trust-all TLS client in Java (legacy twin)

**Severity:** Critical

**Where:**
- `app/src/main/java/com/example/shop/LegacyApi.java:20-26` — anonymous `X509TrustManager` with empty `checkServerTrusted` (line 23)
- `app/src/main/java/com/example/shop/LegacyApi.java:28-31` — `boolean verify(...)` returning `true` (lines 29–30)
- `app/src/main/java/com/example/shop/LegacyApi.java:34-40` — `buildClient()` wires both via `.sslSocketFactory(...)` / `.hostnameVerifier(...)`

**Evidence:**
```java
private final TrustManager[] trustAllCerts = new TrustManager[]{
    new X509TrustManager() {
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        ...
    }
};
private final HostnameVerifier hostnameVerifier = new HostnameVerifier() {
    public boolean verify(String hostname, javax.net.ssl.SSLSession session) {
        return true;
    }
};
```

**Abuse story:** Identical to SEC-001 on the legacy client: any network MITM impersonates
`legacy.example-fake.com` and captures `tokenHeader()` (`"Bearer " + StorageHolder.authToken`,
LegacyApi.java:43-45).

**Fix:** Same as SEC-001 — default trust + pinning (safe shape: `SafeLegacyExamples.pinnedClient()`,
SafeLegacyExamples.java:37-43).

---

### SEC-003 — WebView JS bridge exposes payment and arbitrary file reads to an external URL

**Severity:** Critical

**Where:**
- `app/src/main/java/com/example/shop/BillingWeb.kt:9-13` — `javaScriptEnabled = true`, `addJavascriptInterface(Bridge(), "AppBridge")`, `loadUrl(url)` with a **variable** URL
- `app/src/main/java/com/example/shop/BillingWeb.kt:16-24` — `@JavascriptInterface pay()` reaches the charge processor; `@JavascriptInterface readFile(path)` reaches `FileVault.read(path)`
- In-code comment at BillingWeb.kt:6-7 documents the URL "arrives from a deeplink/intent"

**Evidence:**
```kotlin
fun loadPromo(url: String) {
    webView.settings.javaScriptEnabled = true
    webView.addJavascriptInterface(Bridge(), "AppBridge")
    webView.loadUrl(url)
}
inner class Bridge {
    @JavascriptInterface
    fun pay(payload: String) { ChargeProcessor.submit(payload) }
    @JavascriptInterface
    fun readFile(path: String): String { return FileVault.read(path) }
}
```

**Abuse story:** Any app (or web page in the browser) sends a deeplink that makes this
WebView load an attacker-controlled page. That page's JavaScript calls
`AppBridge.readFile("/data/data/com.example.shop/...")` to read app-private files (e.g. the
plaintext `tokens.txt` from SEC-007) and `AppBridge.pay(payload)` to submit arbitrary charge
payloads from the device.

**Fix:** Don't expose `readFile`/`pay` over the bridge at all; restrict bridge methods to
non-sensitive operations, validate/allowlist the URL before `loadUrl` (constant or
same-origin check), and only add the interface for trusted first-party origins. Safe shape
for loading: `SafeExamples.kt:58-61` (JS disabled, constant https URL).

---

### SEC-004 — Hardcoded AES key in SecretKeySpec

**Severity:** Critical

**Where:**
- `app/src/main/java/com/example/shop/Crypto.kt:9-14` — 14 hardcoded key bytes
- `app/src/main/java/com/example/shop/Crypto.kt:15` — `SecretKeySpec(keyBytes, "AES")`
- Used at `app/src/main/java/com/example/shop/Crypto.kt:17-22` (`encryptLocal`)

**Evidence:**
```kotlin
private val keyBytes = byteArrayOf(
    0x2b, 0x7e, 0x15.toByte(), 0x16, 0x28, 0xae.toByte(), 0xd2.toByte(), 0xa6.toByte(),
    0xab.toByte(), 0xf7.toByte(), 0x15.toByte(), 0x88.toByte(), 0x09.toByte(), 0xcf.toByte()
)
private val secret = SecretKeySpec(keyBytes, "AES")
```

**Abuse story:** The key ships inside the APK; anyone who obtains the APK (app store,
device dump, shared build artifact) extracts the bytes and decrypts everything
`encryptLocal` ever encrypted. The key is also never rotatable without a release.

**Fix:** Generate the key in the Android Keystore with `KeyGenParameterSpec` (safe shape:
`SafeExamples.kt:82-95`) so it is non-exportable and hardware-backed where available.

---

### SEC-005 — AES ECB default via `Cipher.getInstance("AES")`

**Severity:** High

**Where:**
- `app/src/main/java/com/example/shop/Crypto.kt:20-21`

**Evidence:**
```kotlin
val cipher = Cipher.getInstance("AES")
cipher.init(Cipher.ENCRYPT_MODE, secret)
```

**Abuse story:** `"AES"` alone resolves to `AES/ECB/PKCS5Padding`. Identical plaintext
blocks produce identical ciphertext blocks, leaking structure; for small paddable payloads
ECB ciphertext is directly decodable once the key is known (and the key is hardcoded per
SEC-004). Combined SEC-004+SEC-005 means local "encryption" provides no confidentiality.

**Fix:** `Cipher.getInstance("AES/GCM/NoPadding")` with a per-encryption random nonce
(safe shape: `SafeExamples.kt:98-101`).

---

### SEC-006 — Seeded SecureRandom: predictable OTP/token randomness

**Severity:** High

**Where:**
- `app/src/main/java/com/example/shop/Crypto.kt:35-38` — `setSeed(1234567890L)` on a `SecureRandom`

**Evidence:**
```kotlin
fun otpSeed(): SecureRandom {
    val rng = SecureRandom()
    rng.setSeed(1234567890L)
    return rng
}
```

**Abuse story:** `setSeed(constant)` **adds** the constant to the entropy pool rather than
replacing OS entropy, but on this path the output is fully predictable to anyone who knows
the constant and can observe outputs — the method is named `otpSeed`, so OTPs/tokens drawn
from it are guessable, enabling account-takeover via OTP prediction.

**Fix:** Never seed `SecureRandom` on Android; just construct it (safe shape:
`SafeExamples.kt:107`).

---

### SEC-007 — Auth tokens stored in plaintext in three stores (SharedPreferences, file, SQLite)

**Severity:** High

**Where:**
- `app/src/main/java/com/example/shop/Storage.kt:11` — plaintext prefs `"session"`
- `app/src/main/java/com/example/shop/Storage.kt:13-18` — `access_token`/`refresh_token` written to prefs and to `tokens.txt` via `writeText` (line 18)
- `app/src/main/java/com/example/shop/Storage.kt:22,26` — tokens also land in the `session(token TEXT)` SQLite column
- `app/src/main/java/com/example/shop/LegacyStorage.java:11,14-15` — plaintext prefs `"legacy_session"` with `legacy_token`
- `app/src/main/java/com/example/shop/LegacyStorage.java:18-19` — token insert into the same plaintext column

**Evidence:**
```kotlin
private val prefs = context.getSharedPreferences("session", Context.MODE_PRIVATE)
fun persistTokens(accessToken: String, refreshToken: String) {
    prefs.edit().putString("access_token", accessToken).apply()
    prefs.edit().putString("refresh_token", refreshToken).apply()
    val tokenFile = File(context.filesDir, "tokens.txt")
    tokenFile.writeText("access=$accessToken\nrefresh=$refreshToken")
}
```
```java
prefs = context.getSharedPreferences("legacy_session", Context.MODE_PRIVATE);
prefs.edit().putString("legacy_token", accessToken).apply();
```

**Abuse story:** Persona: device thief / rooted device / `adb backup` (or the file-read
bridge in SEC-003). Nothing here is Keystore-backed — plaintext `SharedPreferences` XML, a
plaintext `tokens.txt`, and a plaintext DB column all hold live auth tokens, so recovery of
the userdata partition yields working session credentials. Note that
`security-crypto:1.1.0-alpha06` **is** a dependency (app/build.gradle:23) and the safe shape
exists (`SafeExamples.kt:19-30`, `SafeLegacyExamples.java:17-27`) — the real token stores
simply never use it.

**Fix:** Store tokens in `EncryptedSharedPreferences` with a `MasterKey` (or Android
Keystore-wrapped storage); delete the `tokens.txt` write; if the DB must cache tokens,
store only an encrypted blob or drop the column.

---

### SEC-008 — Deep-link string extra drives `Class.forName` → `startActivity` (arbitrary in-app class instantiation)

**Severity:** High

**Where:**
- `app/src/main/java/com/example/shop/MainActivity.kt:16-19`

**Evidence:**
```kotlin
val target = intent.getStringExtra("screen")
if (target != null) {
    val open = Intent(this, Class.forName("com.example.shop.$target"))
    startActivity(open)
}
```

**Abuse story:** Persona: any other app on the device (component assumed exported; no
manifest present in the fixture to confirm — see NOT assessed). The sender fully controls
`target`, so `Class.forName` resolves **any** class in the package prefix — including
activities never meant to be launched directly (private admin/payment screens) or
side-effectful components — and the app launches it with its own identity and
permissions. `Class.forName` also throws on bad input (crash DoS).

**Fix:** Map the extra through an allowlist of routes to explicit `Class<*>` constants
(safe shape: `SafeExamples.kt:65-73`), and drop reflection entirely.

---

### SEC-009 — Mutable PendingIntent (`flags = 0`)

**Severity:** High

**Where:**
- `app/src/main/java/com/example/shop/MainActivity.kt:24-25`

**Evidence:**
```kotlin
val notify = Intent(this, OrderSyncService::class.java)
val pi = PendingIntent.getActivity(this, 0, notify, 0)
```

**Abuse story:** The **last argument is `0`** — no `FLAG_IMMUTABLE` — so the PendingIntent
is mutable. On pre-Android-12 semantics, another app that obtains a handle to the
notification's intent can rewrite its action/data/component and have **this app's**
identity execute the substituted intent (privilege escalation via the trusted app).

**Fix:** `PendingIntent.getActivity(context, requestCode, intent,
PendingIntent.FLAG_IMMUTABLE)` (safe shape: `SafeExamples.kt:75-78`).

---

### SEC-010 — Local SQL injection: cart-name search interpolated into `execSQL`

**Severity:** High

**Where:**
- `app/src/main/java/com/example/shop/Storage.kt:31-32` — Kotlin string-template interpolation
- `app/src/main/java/com/example/shop/LegacyStorage.java:22-23` — Java concatenation twin
- In-code comment at Storage.kt:29-30 documents that `search()`/`name` "arrives from the deeplink query in MainActivity" (no direct call site exists in the fixture; treated as documented flow per audit rules)

**Evidence:**
```kotlin
fun findCartByName(db: SQLiteDatabase, name: String) {
    db.execSQL("SELECT * FROM carts WHERE name = '$name'")
}
```
```java
db.execSQL("SELECT * FROM carts WHERE name = '" + name + "'");
```

**Abuse story:** External (deeplink-sourced) input is interpolated, not bound. A crafted
name such as `' OR '1'='1` — or `'; DROP TABLE ...`-style stacked statements where the
SQLite build permits — reads or corrupts the app's local DB, which also holds the plaintext
token column (SEC-007). Attacker persona: any other app on the device.

**Fix:** Bind args: `db.execSQL("SELECT * FROM carts WHERE name = ?", arrayOf(name))` /
`rawQuery(sql, selectionArgs)` (safe shapes: `SafeExamples.kt:32-38`,
`SafeLegacyExamples.java:29-35`).

---

### SEC-011 — Local SQL injection: token value interpolated into INSERT

**Severity:** Medium

**Where:**
- `app/src/main/java/com/example/shop/Storage.kt:25-26` — `VALUES ('$accessToken')`
- `app/src/main/java/com/example/shop/LegacyStorage.java:18-19` — `VALUES ('" + accessToken + "')`

**Evidence:**
```kotlin
db.execSQL("INSERT INTO session (token) VALUES ('$accessToken')")
```

**Abuse story:** The token string itself is interpolated. Standalone this is internal-data
injection (Medium), but the token value is server-controlled and SEC-001/SEC-002 let a MITM
deliver an arbitrary "token" string — which then executes as SQL inside the local DB,
chaining to data corruption/exfiltration of the `session` table.

**Fix:** `db.execSQL("INSERT INTO session (token) VALUES (?)", arrayOf(accessToken))`
(safe shapes: `SafeExamples.kt:32-34`, `SafeLegacyExamples.java:29-31`).

---

### SEC-012 — Auth token written to logcat

**Severity:** Medium

**Where:**
- `app/src/main/java/com/example/shop/Api.kt:39-41`

**Evidence:**
```kotlin
fun logSession() {
    Log.d("AUTH", "token: $authToken")
}
```

**Abuse story:** logcat is readable via `adb` on debuggable setups, persists in bug
reports, and is included in some vendor crash dumps — anyone holding those obtains a live
session token. (No `BuildConfig.DEBUG` gate; contrast the safe shape at
`SafeExamples.kt:53`. `LegacyApi.java:48` logs a static message only — verified safe.)

**Fix:** Never log token values; gate any debug logging with `if (BuildConfig.DEBUG)` and
static messages, or remove the call in release builds.

---

### SEC-013 — Cleartext `http://` base URLs for token-bearing API clients

**Severity:** Medium

**Where:**
- `app/src/main/java/com/example/shop/Api.kt:12` — `BASE_URL = "http://api.example-fake.com/v1"`
- `app/src/main/java/com/example/shop/LegacyApi.java:18` — `BASE_URL = "http://legacy.example-fake.com/v1"`

**Evidence:**
```kotlin
const val BASE_URL = "http://api.example-fake.com/v1"
```
```java
public static final String BASE_URL = "http://legacy.example-fake.com/v1";
```

**Abuse story:** Any request to these hosts travels in cleartext; both classes also define
Bearer-token header builders (`authHeader()` Api.kt:35; `tokenHeader()` LegacyApi.java:43-45),
so the intended traffic carries credentials in the clear — passive network observers
harvest tokens. Rated Medium per skill baseline; it escalates to Critical once a call site
attaches the auth header to a BASE_URL request (no such call site exists in the fixture to
confirm the pairing — noted, not assumed). These are not localhost/test values.

**Fix:** Switch both constants to `https://` and add a network security config blocking
cleartext (safe shapes: `SafeExamples.kt:41`, `SafeLegacyExamples.java:15`).

---

### SEC-014 — MD5 used for device fingerprint

**Severity:** Medium

**Where:**
- `app/src/main/java/com/example/shop/Crypto.kt:25-27`

**Evidence:**
```kotlin
fun deviceFingerprint(accountId: String): String {
    val digest = MessageDigest.getInstance("MD5")
```

**Abuse story:** MD5 is collision-broken. Used for a fingerprint, collisions let an
attacker impersonate another account/device identity wherever the fingerprint is trusted
(binding, anti-abuse checks).

**Fix:** `MessageDigest.getInstance("SHA-256")` (safe shape: `SafeExamples.kt:104`).

---

### SEC-015 — SHA-1 used for legacy ticket

**Severity:** Medium

**Where:**
- `app/src/main/java/com/example/shop/Crypto.kt:30-32`

**Evidence:**
```kotlin
fun legacyTicket(accountId: String): String {
    val digest = MessageDigest.getInstance("SHA-1")
```

**Abuse story:** The method issues a *ticket* from a bare SHA-1 of the account id. As an
unkeyed digest this is trivially forgeable by anyone who knows/guesses the account id, and
SHA-1's collision weakness further undermines any integrity assumption. If a ticket
protects more than display identity, severity rises toward Critical.

**Fix:** Replace with an HMAC-SHA-256 keyed by a Keystore-held key, or a server-issued
token; at minimum SHA-256.

---

### SEC-016 — Committed `google-services.json` API key

**Severity:** Medium

**Where:**
- `app/google-services.json:17` — `"current_key": "AIzaFakeForEvalsDoNotUseDoNotUse0000000"`

**Evidence:**
```json
"api_key": [
  { "current_key": "AIzaFakeForEvalsDoNotUseDoNotUse0000000" }
]
```

**Abuse story:** The Firebase Web API key is committed to source control. Firebase API keys
are identifier-level by design, but an unrestricted key with billable APIs enabled is an
attacker-budget risk (quota abuse, enumeration of enabled services). Per audit rules the
planted-looking value is reported as real. Restriction posture cannot be verified from the
repo — hence baseline Medium, not higher.

**Fix:** Restrict the key (Android app package + SHA-1 cert restrictions, per-API enablement),
rotate it, and treat leaked copies as burned. Note the AIza value is required by the google-services
plugin at build time, so pairing restrictions with rotation is the actual control.

---

### SEC-017 — Release build hygiene: no obfuscation, alpha security dependency, no lockfile

**Severity:** Low (informational)

**Where:**
- `app/build.gradle:16` — `minifyEnabled false` in the `release` build type
- `app/build.gradle:23` — `androidx.security:security-crypto:1.1.0-alpha06` (alpha-quality crypto lib in production path)
- No `gradle.lockfile` anywhere in the fixture (verified by file inventory)

**Evidence:**
```groovy
release {
    minifyEnabled false
}
```

**Abuse story:** Unobfuscated release builds make reverse engineering the hardcoded key
(SEC-004) and bridge surface (SEC-003) trivial; an alpha security-crypto version may carry
unfixed issues; without a lockfile, dependency CVE scanning (osv maven ecosystem) can't run.

**Fix:** Enable `minifyEnabled true` + `shrinkResources true` and proguard rules for
release; pin security-crypto to a stable release; commit a `gradle.lockfile` and scan it.

---

## Census receipts

Every scan was run with `--glob '!**/expected-findings.md'`. "hits" = lines returned;
"dispositioned" = each hit mapped to a finding (SEC-NNN) or verified-safe with reason.
All hits dispositioned in every scan (hits == dispositioned throughout).

| # | Step | Scan | hits | dispositioned | Dispositions |
|---|------|------|------|---------------|--------------|
| 1 | S0 | `rg --files -g 'build.gradle*' -g '*.kt' -g '*.java'` (+`google-services.json` glob, scan 3) | 11 | 11 | All 11 files enumerated and fully read (`head -5` shown in run; full set via inventory) |
| 2 | S0 | `rg -n "com.android.application" -g 'build.gradle*'` | 1 | 1 | Native Android app confirmed → Stack summary |
| 3 | S0 | `rg --files -g 'google-services.json'` | 1 | 1 | Committed → SEC-016 |
| 4 | S1 | `getSharedPreferences\(` | 2 | 2 | Storage.kt:11, LegacyStorage.java:11 — credential-class ("session"/"legacy_session" token stores) → SEC-007 |
| 5 | S1 | `writeText\(\|FileOutputStream\(` | 1 | 1 | Storage.kt:18 `tokens.txt` plaintext tokens → SEC-007 |
| 6 | S1 | `SQLiteOpenHelper\|execSQL\(\|rawQuery\(` | 11 | 11 | Storage.kt:26,32 + LegacyStorage.java:19,23 → SEC-010/011; Storage.kt:22 plaintext token column → SEC-007; Storage.kt:5,10 (import/decl), SafeExamples.kt:33,37 + SafeLegacyExamples.java:30,34 (bind args) → verified-safe |
| 7 | S2 | `execSQL\(.*\$` (kt) | 2 | 2 | Storage.kt:26 → SEC-011; Storage.kt:32 → SEC-010 |
| 8 | S2 | `execSQL\(.*\+` (kt+java) | 2 | 2 | LegacyStorage.java:19 → SEC-011; LegacyStorage.java:23 → SEC-010 |
| 9 | S2 | `rawQuery\(.*(\$|\+)` | 0 | 0 | — |
| 10 | S3 | `checkServerTrusted[^{]*\{\}` | 2 | 2 | Api.kt:20 → SEC-001; LegacyApi.java:23 → SEC-002 |
| 11 | S3 | `HostnameVerifier\s*\{[^}]*true` (kt) | 1 | 1 | Api.kt:24 → SEC-001 |
| 12 | S3 | `-A1 "boolean verify"` (java) | 1 | 1 | LegacyApi.java:29-30 `return true;` → SEC-002 |
| 13 | S3 | `http://` | 2 | 2 | Api.kt:12, LegacyApi.java:18 → SEC-013 (not localhost/test) |
| 14 | S4 | `addJavascriptInterface\|@JavascriptInterface` | 3 | 3 | BillingWeb.kt:11,16,21 → SEC-003 (method bodies opened: pay + file read) |
| 15 | S4 | `loadUrl\((url\|target\|[a-z]+Url)` | 1 | 1 | BillingWeb.kt:12 variable URL → SEC-003 (SafeExamples.kt:60 constant URL didn't match — safe near-miss) |
| 16 | S4 | `javaScriptEnabled = true\|setJavaScriptEnabled\(true\)` | 1 | 1 | BillingWeb.kt:10 → SEC-003 (SafeExamples.kt:59 sets false — safe) |
| 17 | S5 | `getStringExtra\(\|getData\(\|getParcelableExtra\(` | 1 | 1 | MainActivity.kt:16 → SEC-008 |
| 18 | S5 | `Class\.forName\|setComponent\(\|setPackage\(` | 1 | 1 | MainActivity.kt:18 → SEC-008 |
| 19 | S5 | `PendingIntent\.getActivity\(` | 2 | 2 | MainActivity.kt:25 flags=0 → SEC-009; SafeExamples.kt:76-77 FLAG_IMMUTABLE → verified-safe (last arg checked) |
| 20 | S6 | `SecretKeySpec\(` | 1 | 1 | Crypto.kt:15 hardcoded bytes → SEC-004 |
| 21 | S6 | `Cipher\.getInstance\("AES"\)` | 1 | 1 | Crypto.kt:20 ECB default → SEC-005 |
| 22 | S6 | `getInstance\("(MD5\|SHA-1)"\)` | 2 | 2 | Crypto.kt:26 → SEC-014; Crypto.kt:31 → SEC-015 |
| 23 | S6 | `setSeed\(` | 1 | 1 | Crypto.kt:37 constant seed → SEC-006 |
| 24 | S7 | `current_key\|api_key` in google-services.json | 2 | 2 | :15 key array, :17 `current_key` value → SEC-016 |
| 25 | S7 | `Log\.[dvi]\([^)]*[Tt]oken` | 1 | 1 | Api.kt:40 token value in Log.d → SEC-012 (LegacyApi.java:48 + MainActivity.kt:30 log static strings — read and verified safe, not scan hits) |
| 26 | S7 | hardcoded `(api[_-]?key\|secret\|token)\s*=\s*"[^"]{8,}"` in kt/java/strings.xml/build.gradle | 0 | 0 | — (no strings.xml exists) |
| 27 | S8 | build.gradle dependency review (manual read) | 3 deps | 3 deps | okhttp 4.12.0, security-crypto 1.1.0-alpha06, webkit 1.10.0 → SEC-017 + NOT-assessed limitation |

Severity tally: **4 Critical** (SEC-001, SEC-002, SEC-003, SEC-004), **6 High** (SEC-005,
SEC-006, SEC-007, SEC-008, SEC-009, SEC-010), **6 Medium** (SEC-011, SEC-012, SEC-013,
SEC-014, SEC-015, SEC-016), **1 Low** (SEC-017) — 17 findings total.

## NOT assessed

- **AndroidManifest.xml** — absent from the fixture; exported-component surface, `allowBackup`, `usesCleartextTraffic`, and network security config (manifest/platform half, `../mobile-security/SKILL.md` scope) could not be audited. SEC-008/SEC-009 assume an exported entry point exists; if none does, their abuse stories degrade.
- **Dependency CVEs** — no `gradle.lockfile` exists, so `dependency-vulns` osv_scan cannot run; manual OSV lookup of `okhttp:4.12.0`, `security-crypto:1.1.0-alpha06`, `webkit:1.10.0` was not performed (offline audit); noted as a limitation per skill Step 8. No CVE claims are made.
- **Runtime/build verification** — the fixture was not compiled or run; referenced-but-absent symbols (`OrderSyncService`, `R.layout.activity_main`, `ChargeProcessor.submit`/`FileVault.read` stubs) mean this is a source-shape fixture, not a buildable app. No dynamic testing, no Frida/objection, no APK analysis.
- **Call-site completeness** — no call sites exist for `persistTokens`, `insertToken`, `findCartByName`, `BillingWeb.loadPromo`, `Api.client()`, or `Crypto.encryptLocal`; the external-input provenance for SEC-003 and SEC-010 rests on in-code comments (treated as documented-real per audit instructions, flagged here for transparency).
- **Strings/resources & proguard files** — no `res/` directory or proguard files exist in the fixture.
- **Blind hygiene confirmation** — `expected-findings.md` was never opened, read, grepped, or catted; it was excluded from every scan and no command printed its contents.
