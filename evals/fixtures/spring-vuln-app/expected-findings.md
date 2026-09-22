# spring-vuln-app — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Hardcoded datasource password in properties | application.properties:2 | Critical |
| 2 | Actuator fully exposed (`*` — env/heapdump leak secrets) | application.properties:5 | Critical |
| 3 | Stacktraces returned to clients | application.properties:8 | Medium |
| 4 | Session cookie without `Secure` | application.properties:11 | Medium |
| 5 | CSRF disabled | SecurityConfig.java:10 | High |
| 6 | `permitAll()` on `/admin/**` | SecurityConfig.java:12 | Critical |
| 7 | JPQL injection via concatenation | UserController.java:20-21 | Critical |
| 8 | XSS via `th:utext` | user.html:4 | High |
| 9 | EOL Spring Boot 2.2.5 + Spring 5.2.x (Spring4Shell-range via vuln-db) | pom.xml:9 | High |
| 10 | Security config likely inert — `WebSecurityConfigurerAdapter` subclass without `@Configuration`/`@EnableWebSecurity` annotation (defaults apply, chain may not register) | SecurityConfig.java:7 | High |

## Must NOT trigger

- `th:text` (escaped counterpart)
- `new UserController(EntityManager)` constructor injection (good practice)
