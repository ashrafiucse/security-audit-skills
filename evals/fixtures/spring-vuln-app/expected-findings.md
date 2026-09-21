# spring-vuln-app — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Hardcoded datasource password in properties | application.properties:2 | Critical |
| 2 | Actuator fully exposed (`*` — env/heapdump leak secrets) | application.properties:5 | Critical |
| 3 | Stacktraces returned to clients | application.properties:8 | Medium |
| 4 | Session cookie without `Secure` | application.properties:11 | Medium |
| 5 | CSRF disabled | SecurityConfig.java:13 | High |
| 6 | `permitAll()` on `/admin/**` | SecurityConfig.java:15 | Critical |
| 7 | JPQL injection via concatenation | UserController.java:20-21 | Critical |
| 8 | XSS via `th:utext` | user.html:5 | High |
| 9 | Spring Boot 2.2.5 / Spring 5.2.x (live OSV; Spring4Shell-range check via vuln-db) | pom.xml | High (network-dependent) |

## Must NOT trigger

- `th:text` (escaped counterpart)
- `new UserController(EntityManager)` constructor injection (good practice)
