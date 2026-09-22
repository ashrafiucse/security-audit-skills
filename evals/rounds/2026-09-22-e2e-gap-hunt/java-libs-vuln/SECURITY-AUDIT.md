# Security Audit — java-libs-vuln (fixture)
Date: 2026-09-22 | Scope: working tree @433fb22 | Auditor: security-skills v1.2.0-14-g433fb22
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: OSV.dev + CISA KEV — NOT RUN (no network; offline KB used)

## Stack
Java/Maven micro-component (`pom.xml`, no framework wiring — plain controller-style classes).
Dependencies: fastjson 1.2.68, commons-text 1.9, shiro-core 1.2.4. Two source files:
`ApiController` (vulnerable paths) and `SafeController` (counter-examples).
No HTTP/servlet configuration, no config files, no Docker/IaC, no logging surface.

## Summary
| Severity | Count |
|---|---|
| Critical | 2 |
| High | 2 |
| Medium | 1 |

Chains: **Shiro550 default key → forged rememberMe cookie → unauthenticated deserialization RCE** (complete);
**fastjson global-autoType + user JSON → RCE** (complete); **Text4Shell ${script:} → RCE** (complete on this version).
All three are independent RCE-class paths in one component.

## Findings

### SEC-001: fastjson autoType enabled + user JSON parsed — RCE (CVE-2022-25845) — CRITICAL
- **Where:** `pom.xml:13` (fastjson 1.2.68), `src/main/java/com/example/web/ApiController.java:15-16`
- **CWE:** CWE-502 (Deserialization of Untrusted Data); OWASP A08/A03
- **Evidence:**
  ```java
  ParserConfig.getGlobalInstance().setAutoTypeSupport(true); // SEC-01a
  return JSON.parseObject(requestBody);                       // SEC-01b: @type honored
  ```
- **Impact:** With `autoTypeSupport(true)`, `@type` tags in the request body instantiate arbitrary
  classes — gadget-chain RCE. **Blast radius is JVM-global**: `ParserConfig.getGlobalInstance()`
  reconfigures the shared parser, so ANY other component parsing untrusted JSON in the same JVM
  becomes exploitable too, not just `parseProfile`. Version 1.2.68 is in the affected range
  (≤1.2.80, vuln-db entry CVE-2022-25845); on this line even the autoType "guards" are
  historically bypassable. Reachability: LIVE — the method parameter is named/used as a request body.
- **Fix:** Remove the `setAutoTypeSupport(true)` line entirely; parse into an explicit type
  (`JSON.parseObject(body, ProfileDTO.class)` — the pattern `SafeController.parseProfile` already
  demonstrates). Upgrade fastjson to ≥1.2.83, or migrate to fastjson2. If polymorphic parsing is a
  hard requirement, restrict via `ParserConfig.getGlobalInstance().addAccept("com.yourpkg.")`
  allowlists only.
- **References:** CVE-2022-25845; vuln-db entry 2022-06-14-cve-2022-25845

### SEC-002: Text4Shell — user text through default StringSubstitutor (CVE-2022-42889) — HIGH
- **Where:** `pom.xml:19` (commons-text 1.9), `src/main/java/com/example/web/ApiController.java:22-24`
- **CWE:** CWE-94 (Code Injection); OWASP A03
- **Evidence:**
  ```java
  StringSubstitutor sub = StringSubstitutor.createDefault();
  return sub.replace(userText); // ${script:...} executes
  ```
- **Impact:** Default lookup factories include script/dns/url — user-supplied text containing
  `${script:...}` executes code; `${dns:...}/${url:...}` give exfiltration/SSRF channels.
  Reachability: LIVE (`renderTemplate(userText)` is caller-supplied).
- **Fix:** Upgrade commons-text to ≥1.10.0 AND construct the substitutor with explicit safe
  lookups only (the `SafeController.renderTemplate` map-lookup pattern). Strip `${...}` from
  user input before substitution as defense in depth.
- **References:** CVE-2022-42889; vuln-db entry 2022-10-13-cve-2022-42889

### SEC-003: Shiro550 — rememberMe cipher key is the well-known default (CVE-2016-4437) — CRITICAL
- **Where:** `pom.xml:25` (shiro-core 1.2.4), `src/main/java/com/example/web/ApiController.java:28-34`
- **CWE:** CWE-798 (Hardcoded Credentials) + CWE-502; OWASP A02/A07/A08
- **Evidence:**
  ```java
  byte[] key = java.util.Base64.getDecoder()
          .decode("kPH+bIxk5D2deZiIxcaaaA=="); // SEC-03: well-known default key
  ...
  rem.setCipherKey(key);
  ```
- **Impact:** The rememberMe cookie is AES-CBC encrypted with a **publicly documented default
  key**. Anyone can craft a serialized object (gadget chain), encrypt it with this key, and send
  it as a rememberMe cookie → **unauthenticated deserialization RCE** on the security manager's
  host. Shiro 1.2.4 is pre-fix for CVE-2016-4437; the CBC padding-oracle variant (CVE-2019-12422)
  additionally affects ≤1.4.1, so even a custom key on this version line leaves an oracle path.
- **Fix:** Upgrade shiro-core to a current 1.x/2.x line AND generate a unique random 32-byte key
  injected from env/secret manager (`setCipherKey(Base64.decode(<random>))`). Rotating the key
  invalidates all rememberMe sessions — that is correct behavior, do it.
- **References:** CVE-2016-4437, CVE-2019-12422; vuln-db entry 2016-06-01-cve-2016-4437

### SEC-004: No resolved-dependency record (Maven "lockfile" absence) — MEDIUM
- **Where:** `pom.xml` (whole file — no resolved-versions record alongside)
- **CWE:** CWE-1104 / CWE-1357; OWASP A06
- **Evidence:** Single `pom.xml` with loose version pins; no `mvn dependency:tree` output, no
  CI-pinned resolved versions, no lockfile-equivalent committed.
- **Impact:** Builds resolve ranges/transitives at build time — the three CVEs above are the
  *direct* pins only; transitive positions are unauditable from the repo and can drift between
  builds (supply-chain replay risk).
- **Fix:** Commit resolved versions (e.g., `mvn dependency:tree` output in CI, or a
  versions-lock plugin / `mvnw` with `--no-transfer-progress` pinned build), so audits and CI
  see exactly what ships.

### SEC-005: Global parser side-effect on security-relevant config (design note) — HIGH (chain-critical component)
- **Where:** `src/main/java/com/example/web/ApiController.java:15`
- **CWE:** CWE-1188 (Insecure Default Initialization); OWASP A05
- **Evidence:** `ParserConfig.getGlobalInstance().setAutoTypeSupport(true);` — static/global
  mutation inside a request-path method.
- **Impact:** Standalone: mutable global security config in a handler (any code path reaching
  this method permanently weakens the JVM's JSON parsing). As a chain component with SEC-001 it
  is what converts a local parsing bug into a JVM-wide RCE surface — tagged **chain-critical**.
- **Fix:** Never mutate global ParserConfig from request code; if polymorphic parsing is needed,
  isolate it in a dedicated `ParserConfig` instance scoped to one endpoint with an allowlist.

## What looks good
- `SafeController` demonstrates the correct patterns for all three libraries: typed
  `JSON.parseObject(body, ProfileDTO.class)` (no `@type` instantiation), `StringSubstitutor`
  built from an explicit map lookup (no script/dns/url factories), and no default-key usage.
- No hardcoded provider credentials or secrets detected by the scanner (the Shiro key is a
  *default crypto key*, reported via SEC-003 rather than as a leaked credential).
- No dangerous usage of the safe parse paths was found in `SafeController` (verified, not assumed).

## OWASP 2021 completeness gate
A01 not assessed (no authz surface — no routes wired); A02 → SEC-003; A03 → SEC-001, SEC-002;
A04 no surface (no business flows); A05 → SEC-005; A06 → SEC-001..004 (versions + no lock);
A07 → SEC-003 (authn forgery path); A08 → SEC-001, SEC-003; A09 no surface (no logging);
A10 no surface (no outbound fetch).

## Recommended fix order
1. SEC-003 (critical, S) — rotate Shiro key + upgrade; forged-cookie RCE is unauthenticated
2. SEC-001 (critical, S) — delete the global autoType line; typed parse already exists in-repo
3. SEC-002 (high, S) — upgrade commons-text + restricted-lookup substitutor (pattern in-repo)
4. SEC-004 (medium, M) — commit resolved dependency versions
5. SEC-005 (high, S) — falls away automatically once SEC-001's global mutation is removed
