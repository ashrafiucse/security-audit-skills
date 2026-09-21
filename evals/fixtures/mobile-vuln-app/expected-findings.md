# mobile-vuln-app — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | `allowBackup="true"` | AndroidManifest.xml:9 | Medium |
| 2 | `debuggable="true"` in app manifest | AndroidManifest.xml:10 | High |
| 2b | Cleartext traffic permitted (manifest + network_security_config) | AndroidManifest.xml:11, res/xml | Medium |
| 3 | Exported `AdminActivity` without permission | AndroidManifest.xml:16 | High |
| 4 | `DeepLinkActivity` with intent-filter (implies exported), handles external scheme | AndroidManifest.xml:20-26 | High |
| 5 | Exported provider + `grantUriPermissions` | AndroidManifest.xml:29-33 | High |
| 5b | Exported `SyncService` | AndroidManifest.xml:35 | High |
| 6 | Hardcoded payment API key in code | MainActivity.kt:6 | Critical |
| 7 | WebView: JS bridge + file access + `intent.dataString` URL (RCE bridge class) | MainActivity.kt:10-14 | Critical |
| 8 | ATS disabled (`NSAllowsArbitraryLoads`) | Info.plist:8-11 | Medium |
| 9 | Auth token in UserDefaults | AppDelegate.swift:9 | Medium/High |

## Must NOT trigger

- `CFBundleDisplayName` string (not a finding)
- The fake domain `update.example-fake.com` itself (only the http:// + JS-enabled combination matters)
