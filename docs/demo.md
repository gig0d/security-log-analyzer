# Demonstration walkthrough

Install from the README, then run from PowerShell in the clone:

```powershell
$sla = ".\.venv\Scripts\security-log-analyzer.exe"
& $sla demo --json
```

The command creates `data/demo-inputs`, imports both sources into `data/demo.db`,
runs six rules, and emits labeled evaluation. It refuses to overwrite different
existing inputs. Repeating it against the same dataset inserts no events/alerts.
Use a fresh or existing demo-only database: evaluation rejects mixed unrelated data.

## Expected data

53 normalized events: 22 SSH, 31 HTTP; 28 benign, 25 scenario records.
Eight alerts: 4 HIGH and 4 MEDIUM. Spraying also triggers brute force independently.

| Scenario | Source | Behavior |
| --- | --- | --- |
| Normal SSH | `203.0.113.1`–`.8` | Eight successful public-key logins, no alerts |
| Normal HTTP | `203.0.113.20`–`.22` | Twenty ordinary requests, no alerts |
| SSH brute force | `192.0.2.10` | Five failures targeting root |
| SSH spraying | `192.0.2.20` | Five failures targeting distinct fictional accounts |
| SSH success after failure | `192.0.2.30` | Three failures and success for operator |
| HTTP enumeration | `198.51.100.10` | Four sensitive paths |
| Suspicious HTTP | `198.51.100.20` | Two inert request-target indicators |
| HTTP authentication abuse | `198.51.100.30` | Five 401 responses at /login |

Seed 42 and reference `2026-01-15T12:00:00+00:00` fix all data. The same generator
creates `examples/auth.log`, `examples/access.log`, and separate `ground-truth.json`.
Labels are not used by ingestion/detection. Nothing creates traffic to real targets.

## Investigate and export

```powershell
& $sla alerts --db data/demo.db --json
& $sla events --db data/demo.db --source ssh --search root --json
$result = & $sla alerts --db data/demo.db --rule SSH_SUCCESS_AFTER_FAILURE --json | ConvertFrom-Json
$alertId = $result.alerts[0].id
& $sla show $alertId --db data/demo.db --json
& $sla status $alertId INVESTIGATING --db data/demo.db --note "Checking expected operator activity"
& $sla detect --db data/demo.db --json
& $sla report --db data/demo.db --alert-id $alertId --filename incident.json
& $sla report --db data/demo.db --format csv --filename alerts.csv
```

The selected alert has four evidence records, three failures plus success.
Inspect source references and rationale rather than assuming compromise. Reanalysis
reports zero new alerts and preserves INVESTIGATING. Reports identify the database,
requested/observed period, actual statistics, and generation time.

Incident JSON includes the alert, rationale, latest 100 status changes, all evidence,
and up to 100 source references per event with total reference counts. Its evidence
scope is independent of summary-period filters. CSV contains an alert summary with
formula-safe fields. Filenames must be plain names inside the chosen output directory.

## Dashboard

```powershell
$env:SLA_DATABASE = "data/demo.db"
.\.venv\Scripts\python.exe -m streamlit run dashboard.py
```

At `http://127.0.0.1:8501`, Overview shows actual metrics/charts. Security alerts
filters by severity/status/rule/IP/search and the sidebar's time range, displays
evidence, and saves investigation decisions. Log explorer filters source/time/IP/
search with 50-row pages. Detection rules shows effective settings and limits.
Reports downloads JSON/CSV; choose Incident and paste an actual alert ID.

The sidebar accepts timezone-aware ISO timestamps. The dataset has fixed dates,
so filtering for today will usually exclude it. Select the intended database when
switching between demo and authorized real logs.

To import the checked-in inputs manually:

```powershell
& $sla ingest examples --db data/manual-demo.db --json
& $sla detect --db data/manual-demo.db --json
```

Flat discovery selects the two `.log` files and ignores JSON labels. Keep real logs
in ignored local directories and review reports before sharing. See [testing](testing.md)
for the fixture evaluation method and measured limitations.
