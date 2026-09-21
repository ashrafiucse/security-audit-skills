# dep-manifests — Expected results

Parser coverage fixture: 3 lockfile formats, 6 unique package@version pairs total
(gradle 3, swift 1, conan 2). The `empty=annotationProcessor` line must be ignored.

| Must be detected | Source | Notes |
|---|---|---|
| `Maven:org.apache.logging.log4j:log4j-core@2.14.1` | gradle.lockfile | Log4Shell range → OSV must return advisories (network) |
| `Maven:org.springframework:spring-webmvc@5.3.16` | gradle.lockfile | parse only |
| `SwiftURL:https://github.com/Alamofire/Alamofire.git@5.6.4` | Package.resolved (v2) | parse only |
| `ConanCenter:openssl@1.1.1k` | conan.lock | revision hash must be stripped |
| `ConanCenter:zlib@1.2.11` | conan.lock | parse only |

Script self-check (also enforced in CI):
- output contains "6 unique package@version pairs"
- output contains "log4j-core@2.14.1" with at least one [VULN] advisory
