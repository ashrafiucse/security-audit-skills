# Security Audit — spring-vuln-app
Date: 2026-09-22 | Scope: working tree (eval fixture dir) | Auditor: security-skills (subagent round)
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: OSV.dev + CISA KEV — NOT RUN (no network)

## Stack
Spring Boot 2.2.5.RELEASE (parent pom; Spring Framework 5.2.x line) · Spring Security (WebSecurityConfigurerAdapter style) · Spring Data JPA + PostgreSQL (Thymeleaf template) · 2 HTTP routes (`/search`, `/admin/keys`) · No Docker/IaC/CI files · No git metadata in fixture.

## Summary
| Severity | Count |
|---|---|
| Critical | 4 |
| High | 3 |
| Medium | 3 |
| Low | 2 |

**Chains (completed):** `permitAll(/admin/**) + /admin/keys` → unauthenticated internal endpoint (chain-critical) · `actuator include=* + hardcoded datasource password` → authenticated user reads every property + in-memory secrets → DB takeover · `JPQL SQLi + include-stacktrace=always` → error-aided SQL extraction.

## Findings

### SEC-001: JPQL injection via string concatenation — CRITICAL
- **Where:** `src/main/java/com/example/web/UserController.java:18-19`
- **CWE:** CWE-89 (SQL Injection)
- **Evidence:**
  ```java
  return em.createQuery(
      "SELECT u FROM User u WHERE u.name = '" + q + "'").getResultList();
  ```
- **Impact:** `@RequestParam q` is concatenated into JPQL — an authenticated user submits `x' OR '1'='1` (or JPQL function abuse `... OR u.role = 'ADMIN'`) to read/modify every User row. Reachable at `GET /search` (authenticated by `anyRequest()`, likelihood: any logged-in user).
- **Fix:** `em.createQuery("SELECT u FROM User u WHERE u.name = :name").setParameter("name", q)` — bound parameters, always.
- **References:** OWASP A03, CWE-89

### SEC-002: `/admin/**` open to everyone — CRITICAL (chain-critical)
- **Where:** `src/main/java/com/example/config/SecurityConfig.java:12` (handler at `UserController.java:22-24`)
- **CWE:** CWE-862 (Missing Authorization)
- **Evidence:**
  ```java
  .antMatchers("/admin/**").permitAll()          // SEC-06
  ```
- **Impact:** `GET /admin/keys` is reachable unauthenticated. The handler returns a constant here, but the route name and pattern expose every current/future admin handler to anyone. Completes the report's first chain by itself.
- **Fix:** `.antMatchers("/admin/**").hasRole("ADMIN")` (plus method-level `@PreAuthorize("hasRole('ADMIN')")` on handlers for defense in depth).
- **References:** OWASP A01, CWE-862

### SEC-003: Actuator endpoints fully exposed — CRITICAL
- **Where:** `src/main/resources/application.properties:6`
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Evidence:**
  ```properties
  management.endpoints.web.exposure.include=*
  ```
- **Impact:** `/actuator/env` prints every property (including `spring.datasource.password`, SEC-004) and `/actuator/heapdump` dumps in-memory secrets to anyone who passes the filter chain (any authenticated session on the shared port; commonly wide open once a separate management port exists). Chains with SEC-004 → full DB credential compromise.
- **Fix:** `management.endpoints.web.exposure.include=health,info` (+ dedicated secured management port); never expose `env`, `heapdump`, `shutdown`.
- **References:** OWASP A05, CWE-200

### SEC-004: Hardcoded database password — CRITICAL
- **Where:** `src/main/resources/application.properties:3`
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Evidence:**
  ```properties
  spring.datasource.password=spring-prod-pass-2026
  ```
- **Impact:** Committed credential — anyone with repo access (clones, forks, CI logs, and SEC-003's `/actuator/env`) gets prod DB access. (File header says "FAKE values", but the value is realistic and committed — treat as real until rotated.)
- **Fix:** Move to env/secret manager (`spring.datasource.password=${DB_PASSWORD}`), rotate the credential, scrub history (`git filter-repo`/BFG).
- **References:** OWASP A07, CWE-798

### SEC-005: CSRF disabled with session cookies — HIGH
- **Where:** `src/main/java/com/example/config/SecurityConfig.java:10`
- **CWE:** CWE-352 (CSRF)
- **Evidence:**
  ```java
  http.csrf().disable()                              // SEC-05
  ```
- **Impact:** Session-cookie auth + no CSRF token: any site can silently drive an authenticated user's browser against state-changing endpoints. Precondition: this app currently exposes GET-only handlers — the risk materializes with the first POST (flag now, it is one annotation away).
- **Fix:** Remove `csrf().disable()`; if a public API is intended, split the filter chain and use token auth for it instead of disabling CSRF globally.
- **References:** OWASP A01, CWE-352

### SEC-006: Unescaped Thymeleaf output — HIGH
- **Where:** `src/main/resources/templates/user.html:4`
- **CWE:** CWE-79 (XSS)
- **Evidence:**
  ```html
  <p th:utext="${user.bio}">bio</p>
  ```
- **Impact:** `th:utext` bypasses Thymeleaf auto-escaping on a model field — any path that writes user content into `user.bio` becomes stored XSS (session/actions of viewers). No write path exists in this codebase yet (read-side sink confirmed).
- **Fix:** `th:text` (as the neighboring line already does).
- **References:** OWASP A03, CWE-79

### SEC-007: Stacktraces returned to clients — MEDIUM
- **Where:** `src/main/resources/application.properties:9`
- **CWE:** CWE-209 (Information Exposure Through Error)
- **Evidence:** `server.error.include-stacktrace=always`
- **Impact:** Full stack traces (class paths, SQL fragments, library versions) to every requester — directly aids SEC-001 error-based exploitation and recon.
- **Fix:** `server.error.include-stacktrace=never` (log server-side instead).

### SEC-008: Session cookie without Secure flag — MEDIUM
- **Where:** `src/main/resources/application.properties:12`
- **CWE:** CWE-614 (Sensitive Cookie without Secure Flag)
- **Evidence:** `server.servlet.session.cookie.secure=false`
- **Impact:** Session cookie transmitted over plain HTTP on any http:// request → interception on non-TLS hops.
- **Fix:** `secure=true` (+ `same-site=lax`), serve behind HTTPS.

### SEC-009: Cleartext JDBC to database — MEDIUM
- **Where:** `src/main/resources/application.properties:2`
- **CWE:** CWE-319 (Cleartext Transmission)
- **Evidence:** `spring.datasource.url=jdbc:postgresql://db.internal.example.com/app`
- **Impact:** No `sslmode` — credentials and query data cross the network unencrypted (internal-network sniffing/compromise).
- **Fix:** `jdbc:postgresql://...?sslmode=verify-full` with a trusted CA.

### SEC-010: EOL Spring Boot 2.2.5 + Spring4Shell-range framework — HIGH
- **Where:** `pom.xml:9`
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components)
- **Evidence:**
  ```xml
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>2.2.5.RELEASE</version>
  ```
- **Impact:** Boot 2.2.5 (Feb 2020) is on the EOL 2.x line (OSS support ended Dec 2023) — no security fixes. Bundled Spring Framework 5.2.x (<5.2.20) falls in the CVE-2022-22965 (Spring4Shell, RCE) affected range when run on JDK 9+ deployed as WAR on Tomcat; verify deployment shape. Live OSV/KEV checks not run (offline) — other dependency CVEs likely.
- **Fix:** Upgrade to a supported Boot line (3.x / latest 2.7.x patch at minimum) and re-scan with OSV.
- **References:** CVE-2022-22965 (conditional), OWASP A06

### SEC-011: Security config may not be registered — LOW (Possible — needs verification)
- **Where:** `src/main/java/com/example/config/SecurityConfig.java:7`
- **CWE:** CWE-1188 (Insecure Default Initialization)
- **Evidence:** `public class SecurityConfig extends WebSecurityConfigurerAdapter {` — no `@Configuration`/`@EnableWebSecurity` annotation present.
- **Impact:** If the class is not component-scanned, none of this config applies (Boot default = all requests authenticated) — either way the code as written misleads. Verify bean registration at runtime.
- **Fix:** Annotate with `@Configuration` + `@EnableWebSecurity` and add a test asserting `/admin/keys` returns 401/403.

### SEC-012: No audit logging / rate limiting — LOW
- **Where:** `src/main/java/com/example/web/UserController.java:15-24` (no logging anywhere in app)
- **CWE:** CWE-778 (Insufficient Logging)
- **Impact:** Admin-endpoint access and failed/suspicious requests leave no trace (compounds SEC-002: unauthenticated admin access is also undetectable); `/search` has no rate limit (authenticated abuse only).
- **Fix:** Structured audit log for admin/auth events; rate-limit `/search`.

## OWASP completeness gate
| Cat | Status |
|---|---|
| A01 Broken Access Control | findings: SEC-002, SEC-005 |
| A02 Cryptographic Failures | findings: SEC-004, SEC-008, SEC-009 |
| A03 Injection | findings: SEC-001, SEC-006 |
| A04 Insecure Design | limited (SEC-012 rate-limit note) |
| A05 Security Misconfiguration | findings: SEC-003, SEC-007 |
| A06 Vulnerable Components | finding: SEC-010 (offline check only) |
| A07 Auth Failures | no login/auth endpoints in app — surface limited; cookie flags covered (SEC-008) |
| A08 Data Integrity | no deserialization/SpEL/supply-chain surface — not assessed |
| A09 Logging | finding: SEC-012 (no logging at all) |
| A10 SSRF | no outbound fetch surface — not assessed |

## What looks good
- Default-deny posture for non-admin routes (`anyRequest().authenticated()`, SecurityConfig.java:13)
- Thymeleaf auto-escaping used correctly on the sibling field (`th:text`, user.html:5)
- No deserialization, SpEL-parsing, or command-execution sinks anywhere
- Dependencies via managed starter poms (no ad-hoc version drift within the app's own deps)

## Recommended fix order
1. SEC-002 permitAll → hasRole (S effort, kills a chain)
2. SEC-001 bound JPQL parameters (S)
3. SEC-004 rotate + externalize password, SEC-003 shrink actuator exposure (S/M)
4. SEC-010 platform upgrade planning (L)
5. SEC-005/006/007/008/009 hardening batch (S each)
6. SEC-011/012 verification + logging (S)
