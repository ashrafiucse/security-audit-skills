# java-libs-vuln — Expected findings

Ground truth for `evals/fixtures/java-libs-vuln` (vuln-db library families:
fastjson, commons-text, shiro). Live OSV results informational — versions are
planted for the code-signal checks below.

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | fastjson autoType enabled + user JSON parsed — CVE-2022-25845 RCE family | pom.xml:13 (1.2.68), ApiController.java:15-17 | Critical |
| 2 | Text4Shell — `StringSubstitutor.createDefault().replace(userText)` with script/dns/url lookups — CVE-2022-42889 | pom.xml:19 (commons-text 1.9), ApiController.java:22-24 | High |
| 3 | Shiro550 — rememberMe cipher key set to the well-known default `kPH+bIxk5D2deZiIxcaaaA==` — CVE-2016-4437 | pom.xml:25 (shiro 1.2.4), ApiController.java:28-34 | Critical |
| 4 | No resolved-dependency record — loose pins in `pom.xml`, no lockfile-equivalent committed (file-level anchor) | pom.xml:- | Medium |

## Must NOT trigger (near-misses — `SafeController.java`)

- `JSON.parseObject(body, ProfileDTO.class)` — typed parse, no autoType
- `StringSubstitutor` built with an explicit map lookup (`${env}` only)
- No `setCipherKey`-with-default-key pattern in the safe file
