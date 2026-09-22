# Security Audit — mobile-vuln-app
Date: 2026-09-22 | Scope: working tree | Auditor: security-skills (subagent round)
Knowledge base: 33 vuln-db entries (newest 2026-09-11) | Live checks: NOT RUN (no network — OSV.dev + CISA KEV skipped)

## Stack
Android app (`com.example.vulnapp`, Kotlin) + iOS counterpart (Swift) — fixture-grade mini-app, 5 files.
Surfaces: `AndroidManifest.xml` (4 components, 1 permission), `MainActivity.kt` (WebView), `res/xml/network_security_config.xml`, `Info.plist` (ATS), `AppDelegate.swift` (token storage).
No dependency manifests (no `build.gradle`/`Podfile`/`pubspec.yaml`) — dependency scan not applicable. No HTTP backend code in-tree.

## Summary
| Severity | Count |
|---|---|
| Critical | 2 |
| High | 5 |
| Medium | 4 |
| **Total** | **11** |

Attack chains: **3** (2 Critical) — see Chain Analysis after findings.

## Findings

### SEC-001: Hardcoded payment API key — CRITICAL
- **Where:** `MainActivity.kt:6`
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Evidence:**
  ```kotlin
  // SEC-06: hardcoded API key (trivial to extract via decompilation)
  private val PAYMENT_API_KEY = "pk_live_51FakeKeyForEvalFixtureXy9"
  ```
  (Also surfaced by the repo's secrets scanner: `skills/secrets-detection/scripts/scan.sh` flags this line.)
- **Impact:** Anyone with the APK extracts the live payment key via decompilation (one `jadx` command). Payment-key compromise = charge/quota abuse and, for secret keys, full account takeover. Shipping a `pk_live_`-prefixed key in client code means every user has it.
- **Fix:** Remove from source; move payment operations server-side and call them via authenticated API; if a client-side publishable key is truly required, treat it as public (restrict via dashboard allowlists) and never ship secret keys. Rotate the exposed key.
- **References:** CWE-798; OWASP MASVS-STORAGE-1, MASTG "hardcoded keys"

### SEC-002: WebView RCE bridge — JS interface + file access + attacker-influenced URL — CRITICAL
- **Where:** `MainActivity.kt:11-14`
- **CWE:** CWE-749 (Exposed Dangerous Method or Function); CWE-711
- **Evidence:**
  ```kotlin
  webView.settings.javaScriptEnabled = true
  webView.settings.allowFileAccess = true
  webView.addJavascriptInterface(WebBridge(), "AndroidBridge")
  webView.loadUrl(intent?.dataString ?: "http://update.example-fake.com/app")
  ```
- **Impact:** Any page loaded into this WebView can call `AndroidBridge` methods from JavaScript. `addJavascriptInterface` on API < 17 is direct RCE via reflection; on newer APIs any exported bridge method is still a full attack surface — with `allowFileAccess` + attacker-controlled `intent.dataString`, a malicious page (via chain CHAIN-1/2) executes bridge methods and can read local files. Combined with SEC-004/SEC-008 this is remotely triggerable.
- **Fix:** Remove `addJavascriptInterface` (use `postMessage`/`JavascriptEngine` safe channels); if a bridge is unavoidable: annotate only minimal `@JavascriptInterface` methods, validate every argument, set `allowFileAccess=false`, `allowUniversalAccessFromFileURLs=false`, and only `loadUrl` a fixed https allowlist — never `intent.dataString`.
- **References:** CWE-749; MASTG "WebViews" / "JavaScript bridges"

### SEC-003: Exported AdminActivity without permission — HIGH
- **Where:** `AndroidManifest.xml:15`
- **CWE:** CWE-926 (Improper Export of Android Application Components)
- **Evidence:**
  ```xml
  <activity android:name=".AdminActivity" android:exported="true" />
  ```
- **Impact:** Any app on the device (or ADB, or a browser via redirect) starts the admin activity — component hijacking, UI redressing of admin screens, or access to unguarded admin logic.
- **Fix:** `android:exported="false"`; if it must be callable, guard with a `signature`-level permission: `android:permission="com.example.vulnapp.ADMIN"`.
- **References:** CWE-926; MASVS-PLATFORM-2

### SEC-004: DeepLinkActivity exported via intent-filter, handles external scheme — HIGH
- **Where:** `AndroidManifest.xml:18-23`
- **CWE:** CWE-926 / CWE-927 (Intent Redirect)
- **Evidence:**
  ```xml
  <activity android:name=".DeepLinkActivity">
      <intent-filter>
          <action android:name="android.intent.action.VIEW" />
          <data android:scheme="vulnapp" />
      </intent-filter>
  </activity>
  ```
- **Impact:** `<intent-filter>` implies exported: any web page (`<a href="vulnapp://...">`) or installed app fires this handler with fully attacker-controlled data. Combined with SEC-002 (MainActivity loads `intent.dataString` into the bridged WebView) this is the entry point of CHAIN-1 (RCE).
- **Fix:** Keep the handler but validate and canonicalize every deep link against a path allowlist; never forward raw `dataString` into `loadUrl`; mark `android:exported="true"` explicitly (API 31+ requires it) and consider `android:autoVerify` for https links instead of custom schemes.
- **References:** CWE-927; MASTG "Deep links"

### SEC-005: Exported provider with grantUriPermissions — HIGH
- **Where:** `AndroidManifest.xml:26-29`
- **CWE:** CWE-926; CWE-200
- **Evidence:**
  ```xml
  <provider
      android:name=".UserDataProvider"
      android:exported="true"
      android:grantUriPermissions="true" />
  ```
- **Impact:** Any app queries/opens URIs from `UserDataProvider` (name suggests user data) — data disclosure by a one-line ContentResolver call; `grantUriPermissions` additionally allows URI grants to propagate to malicious apps.
- **Fix:** `exported="false"`; scope grants via `<grant-uri-permission android:pathPrefix="/public/">` if partial sharing is needed; enforce per-call permission checks in query/openFile.
- **References:** CWE-926; MASVS-STORAGE-2

### SEC-006: Exported SyncService without permission — HIGH
- **Where:** `AndroidManifest.xml:31`
- **CWE:** CWE-926
- **Evidence:**
  ```xml
  <service android:name=".SyncService" android:exported="true" />
  ```
- **Impact:** Any app starts/stops the sync service at will (battery/DoS abuse) and, worse, can trigger it with crafted intents if `onStartCommand` consumes extras — background logic invoked with attacker data.
- **Fix:** `android:exported="false"` + explicit intent-only invocation internally.
- **References:** CWE-926

### SEC-007: debuggable="true" — HIGH
- **Where:** `AndroidManifest.xml:10`
- **CWE:** CWE-489 (Active Debug Code)
- **Evidence:**
  ```xml
  android:debuggable="true"
  ```
- **Impact:** Debug bridge open on production installs: memory inspection, arbitrary code injection via `run-as`/JDWP, private-data extraction from any device with USB/ADB. Combined with SEC-001 the key is readable even without decompiling.
- **Fix:** Remove the attribute (release builds set it false); enforce via CI check that release manifest has no `debuggable`.
- **References:** CWE-489; MASVS-RESILIENCE-2

### SEC-008: Cleartext traffic permitted everywhere (manifest + network config + http fallback URL) — MEDIUM
- **Where:** `AndroidManifest.xml:11`, `res/xml/network_security_config.xml:4`, `MainActivity.kt:14`
- **CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)
- **Evidence:**
  ```xml
  android:usesCleartextTraffic="true"            <!-- manifest -->
  <base-config cleartextTrafficPermitted="true" />  <!-- network_security_config -->
  ```
  ```kotlin
  webView.loadUrl(intent?.dataString ?: "http://update.example-fake.com/app")
  ```
- **Impact:** Full HTTP downgrade on any network: MITM reads/modifies all traffic. The `http://` update URL feeds the bridged WebView → CHAIN-2 (network attacker reaches the RCE bridge without any deep link).
- **Fix:** `cleartextTrafficPermitted="false"` in base-config, drop `usesCleartextTraffic`, make the update URL `https://`; allow cleartext only for specific dev domains via `domain-config` in debug-overlays.
- **References:** CWE-319; NMM-1/NMM-2

### SEC-009: iOS App Transport Security fully disabled — MEDIUM
- **Where:** `Info.plist:6-10`
- **CWE:** CWE-319
- **Evidence:**
  ```xml
  <key>NSAppTransportSecurity</key>
  <dict>
      <key>NSAllowsArbitraryLoads</key>
          <true/>
  </dict>
  ```
- **Impact:** All iOS HTTP traffic may run in cleartext: MITM intercepts the auth-token exchange and any API data. No `NSExceptionDomains` scoping — blanket opt-out.
- **Fix:** Remove `NSAllowsArbitraryLoads`; per-domain exceptions only with justification, and prefer `NSRequiresCertificateTransparency` for critical domains.
- **References:** CWE-319; ATS documentation

### SEC-010: allowBackup="true" — MEDIUM
- **Where:** `AndroidManifest.xml:9`
- **CWE:** CWE-530 (Exposure of Backup Information to Alternate Control Plane? → Backup of More Sensitive Information)
- **Evidence:**
  ```xml
  android:allowBackup="true"
  ```
- **Impact:** App private data (SharedPreferences, databases — wherever tokens/state live) is extractable via `adb backup` on stock devices and rides cloud auto-backups.
- **Fix:** `android:allowBackup="false"` (or `dataExtractionRules` on API 31+ excluding sensitive files).
- **References:** CWE-530; MASVS-STORAGE-1

### SEC-011: Auth token stored in UserDefaults (plaintext plist, rides backups) — MEDIUM/HIGH
- **Where:** `AppDelegate.swift:9`
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information); value also CWE-798 (hardcoded)
- **Evidence:**
  ```swift
  UserDefaults.standard.set("tok_FakeTokenForEvalFixtures12345", forKey: "auth_token")
  ```
- **Impact:** Session token sits in an unencrypted plist included in iTunes/cloud backups and readable by anything with filesystem access (paired with SEC-009, also interceptable in transit). Token theft = session takeover.
- **Fix:** Store tokens in the Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; never hardcode token values at all — this line both hardcodes and mis-stores.
- **References:** CWE-312; MASVS-STORAGE-2

## Chain Analysis (compound impact)

- **CHAIN-1 — Deep link → WebView bridge RCE (Critical):** web page or app fires `vulnapp://attacker.example` (SEC-004) → activity forwards `intent.dataString` → MainActivity `loadUrl()` into WebView with `javaScriptEnabled` + `addJavascriptInterface` + `allowFileAccess` (SEC-002) → attacker JS calls `AndroidBridge` → code execution / local file read. Fix any one link (ideally the bridge) to break the chain.
- **CHAIN-2 — MITM → same RCE (Critical):** cleartext permitted (SEC-008) + `http://` update URL fallback (MainActivity.kt:14) → network attacker serves the "update" page → SEC-002 bridge. No deep link needed.
- **CHAIN-3 — Backup/traffic token theft (High, iOS):** ATS off (SEC-009) intercepts token in transit; UserDefaults storage (SEC-011) re-exposes it at rest and in backups.
- **CHAIN-4 — key extraction (Critical, trivial):** SEC-001 alone — decompile APK (or SEC-007's debug bridge) → payment key.

## What looks good
- Minimal permission set: only `INTERNET` requested — no camera/location/sms overreach.
- A `network_security_config.xml` exists at all (most apps skip it) — the file just needs its policy flipped.
- No custom permissions declared, so no `protectionLevel="normal"`-guarded sensitive ops.
- `INTERNET`-only + no exported receivers: the attack surface is enumerated and small (all 4 components fixable with one attribute each).

## Not assessed
- **A06 dependencies:** no `build.gradle`/`Podfile`/`pubspec.yaml` in tree — dependency CVE scan not applicable.
- **A09 logging:** no logging code present.
- **Live OSV/CISA KEV checks:** not run (no network in this environment).
- React Native/Flutter storage checks: not applicable (native app).

## Recommended fix order
1. SEC-002 (critical, S) — remove the JS bridge + never load `intent.dataString`; this also breaks CHAIN-1 and CHAIN-2
2. SEC-001 (critical, S) — pull the payment key server-side + rotate
3. SEC-004 + SEC-008 (chain entry points, S each) — deep-link validation; https-only
4. SEC-003/005/006 (high, S each) — one-attribute fixes: `exported="false"`
5. SEC-007 (high, S) — drop `debuggable`
6. SEC-011 (medium, S) — Keychain migration for the token
7. SEC-009, SEC-010, SEC-008 remainder (medium, S) — ATS on, allowBackup off, cleartext off
