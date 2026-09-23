# dotnet-vuln-app — Expected findings

Ground truth for `evals/fixtures/dotnet-vuln-app` (ASP.NET Core 3.1 + legacy
web.config). Vulnerable app files + `Safe*`/`safe-*` counter-examples.
Dependency CVE rows are version+detection claims (offline ground truth);
live OSV results would be informational only.

| # | Class | Finding | Where | Severity |
|---|---|---|---|---|
| 1 | Secrets | DB connection string with embedded password in appsettings (reported by BOTH secrets-detection connstr pattern and dotnet Step 1 grep — attribution split) | appsettings.json:3 | Critical |
| 2 | Authz | `[AllowAnonymous]` on data-returning action (`All`) | Controllers/ReportsController.cs:8 | Critical |
| 3 | Redirect | Open redirect — `Redirect(Request.Query["next"])` unvalidated | Controllers/ReportsController.cs:18 | High |
| 4 | Command | `ProcessStartInfo` with concatenated single-string args (`bash -c "..." + file`) | Controllers/ReportsController.cs:25-26 | High |
| 5 | Mass assignment | `user.Role = model.Role` — privilege field from request model (Umbraco GHSL class) | Controllers/ReportsController.cs:36 | Critical |
| 6 | SQLi | EF Core `FromSqlRaw($"... {author}")` interpolated raw SQL | Data/ReportRepository.cs:15 | Critical |
| 7 | SQLi | Dapper `.Query("... " + title)` string concatenation | Data/ReportRepository.cs:22 | Critical |
| 8 | Deserialization | `BinaryFormatter.Deserialize` on request stream — gadget-chain RCE | Utils/LegacyImporter.cs:10-11 | Critical |
| 9 | XXE | `DtdProcessing = DtdProcessing.Parse` on untrusted XML | Utils/LegacyImporter.cs:17 | High |
| 10 | XSS | Razor `@Html.Raw(Model.Body)` — student-authored body rendered unescaped (direction: unprivileged→staff) | Views/Reports/View.cshtml:4 | Critical |
| 11 | Crypto/config | Hardcoded `machineKey` (validation+decryption literals) → forged `__VIEWSTATE` → pre-auth RCE | web.config:4 | Critical |
| 12 | Config | CORS `AllowAnyOrigin()` + `AllowCredentials()` | Program.cs:25-26 | High |
| 13 | Config | Newtonsoft `TypeNameHandling.All` — polymorphic deserialization on request bodies | Program.cs:29 | Critical |
| 14 | Config | `UseDeveloperExceptionPage()` without environment guard — stacktrace leak | Program.cs:34 | Medium |
| 15 | Dependency CVE | Telerik.Web.UI 2018.3.1010 < 2020.1.114 — CVE-2019-18935 deserialization RCE (KEV); version row only (no handler mapping in fixture → upgrade note, not full CVE finding per entry contract) | dotnet-vuln-app.csproj:8 | High |
| 16 | Secrets | Hardcoded connection string in C# source (same fake-credential finding in both files — pattern-level, independent of the SQL safe/unsafe classes) | Data/ReportRepository.cs:9, Data/SafeReportRepository.cs:9 | Critical |

## Must NOT trigger (near-misses — Safe* files)

- `Data/SafeReportRepository.cs:15` — `FromSqlInterpolated($"... {author}")` is the SAFE parameterizing API (near-miss by API contract, not a finding)
- `Data/SafeReportRepository.cs:22-25` — Dapper with `new { Title = title }` parameter object
- `Views/Reports/SafeView.cshtml:4` — plain `@Model.Body` auto-encodes
- `Controllers/SafeReportsController.cs:7` — `[Authorize(Policy = "Staff")]` present; `:16-18` `Url.IsLocalUrl` guard on redirect; `:25-31` `ArgumentList` additive form; `:41` no `user.Role` assignment
- `Utils/SafeImporter.cs` — `JsonSerializer.Deserialize<T>` + `DtdProcessing.Ignore` + `XmlResolver = null`
- `safe-web.config:4` — `validationKey="AutoGenerate"` (the auto-generated form is the safe shape)
- `appsettings.json` connection string uses a documented fake password (`Fake4EvalsDoNotUse`) — the PATTERN is the finding, triage rule per secrets-detection
