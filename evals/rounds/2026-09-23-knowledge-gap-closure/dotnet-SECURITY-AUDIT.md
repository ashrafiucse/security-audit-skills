# Security Audit — dotnet-vuln-app
Date: 2026-09-23 | Scope: fixture tree | Auditor: security-skills dev (IN-PROCESS run — see scoreboard label; ground-truth-aware artifact validation, not blind recall)

## Stack
ASP.NET Core 3.1 (Razor) + legacy web.config + Telerik.Web.UI 2018.3.1010 / Dapper / Newtonsoft.Json 12.0.2 (dotnet-vuln-app.csproj). Safe counterparts: Safe*Controller/Repository/Importer, SafeView.cshtml, safe-web.config.

## Summary
| Severity | Count |
|---|---|
| Critical | 9 |
| High | 6 |
| Medium | 1 |

## Findings
### SEC-001: DB connection string with embedded password in appsettings — CRITICAL
- **Where:** `appsettings.json:3` — CWE-798 — `Password=Fake4EvalsDoNotUse` inside ConnectionStrings.Default (documented fake; pattern+placement is the finding). Reported by secrets-detection connstr pattern AND dotnet Step 1.

### SEC-002: Hardcoded connection string in C# source — CRITICAL
- **Where:** `Data/ReportRepository.cs:9, Data/SafeReportRepository.cs:9` — CWE-798 — SqlConnection literal in both files (pattern-level finding, independent of the SQL safe/unsafe classes).

### SEC-003: `[AllowAnonymous]` on data-returning action — CRITICAL
- **Where:** `Controllers/ReportsController.cs:8` — CWE-862 — admin data surface `All(title)` exposed without auth.

### SEC-004: Open redirect — HIGH
- **Where:** `Controllers/ReportsController.cs:18` — CWE-601 — `Redirect(Request.Query["next"])` unvalidated.

### SEC-005: Command injection via concatenated ProcessStartInfo args — HIGH
- **Where:** `Controllers/ReportsController.cs:25-26` — CWE-78 — `bash -c "pdf2txt " + file` single-string form.

### SEC-006: Mass assignment of privilege field — CRITICAL
- **Where:** `Controllers/ReportsController.cs:36` — CWE-915 — `user.Role = model.Role` (Umbraco GHSL class).

### SEC-007: EF Core FromSqlRaw interpolated SQLi — CRITICAL
- **Where:** `Data/ReportRepository.cs:15` — CWE-89 — `FromSqlRaw($"... '{author}'")`; `FromSqlInterpolated` is the safe API (SafeReportRepository.cs:15).

### SEC-008: Dapper concatenated SQLi — CRITICAL
- **Where:** `Data/ReportRepository.cs:22` — CWE-89 — `.Query("... '" + title)`; safe: `new { Title }` params (:22-25).

### SEC-009: BinaryFormatter deserialization RCE — CRITICAL
- **Where:** `Utils/LegacyImporter.cs:10-11` — CWE-502 — gadget chains; safe: JSON (SafeImporter.cs:14).

### SEC-010: XXE via DtdProcessing.Parse — HIGH
- **Where:** `Utils/LegacyImporter.cs:17` — CWE-611 — safe: `DtdProcessing.Ignore` + `XmlResolver = null` (SafeImporter.cs:18-19).

### SEC-011: Razor Html.Raw stored XSS — CRITICAL
- **Where:** `Views/Reports/View.cshtml:4` — CWE-79 — unprivileged-authored body rendered unescaped; safe: `@Model.Body` (SafeView.cshtml:4).

### SEC-012: Hardcoded machineKey → ViewState RCE — CRITICAL
- **Where:** `web.config:4` — CWE-321 — literal validation/decryption keys; safe: AutoGenerate (safe-web.config:4).

### SEC-013: CORS AllowAnyOrigin + AllowCredentials — HIGH
- **Where:** `Program.cs:25-26` — CWE-942.

### SEC-014: Newtonsoft TypeNameHandling.All polymorphic deserialization — CRITICAL
- **Where:** `Program.cs:29` — CWE-502 — request-bound type names = gadget surface.

### SEC-015: Developer exception page unconditional — MEDIUM
- **Where:** `Program.cs:34` — CWE-209 — stacktrace leak without environment guard.

### SEC-016: Telerik.Web.UI 2018.3.1010 — CVE-2019-18935 range — HIGH
- **Where:** `dotnet-vuln-app.csproj:8` — CWE-502 — < 2020.1.114 (KEV, unauth deserialization RCE). No handler mapping in fixture → upgrade note, not full CVE finding per entry contract.

## Must NOT trigger (verified clean)
Safe files carry only the escaped/parameterized/AutoGenerate/Authorize/ArgumentList/IsLocalUrl forms; FromSqlInterpolated and `@Model` encoding are API-contract safe shapes.
