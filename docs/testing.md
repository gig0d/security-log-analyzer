# Testing and evaluation

After installing locked development dependencies, run:

```powershell
.\.venv\Scripts\python.exe scripts/check.py
```

The cross-platform runner executes Ruff lint/format, strict MyPy, and Pytest with
statement/branch coverage. Temporary files use ignored `.tools/pytest-check`,
including in sandboxes that restrict the machine's default temp directory.
It requires no PowerShell execution-policy change.

## Recorded local verification

Validation date: **2026-10-20**, Windows, Python **3.13.16**.

- **73 passed, 1 skipped**, with no warnings after closing test-owned SQLite handles.
- **94% combined statement/branch coverage** from 1,173 statements and 330 branches.
- Ruff lint/format and strict MyPy passed for all 13 application modules.
- Hash-locked dependency installation into a clean environment passed.
- Built wheel installed separately; its installed CLI produced 53 events / 8 alerts.
- Streamlit AppTest passed navigation, actual metrics, severity filtering, status
  persistence, and empty/invalid-period handling. Server health returned `ok`.
  Browser screenshot inspection was unavailable in the development session.
- PyPA `pip-audit` found no known installed-package vulnerabilities at review time;
  this advisory result is not a security guarantee.

The skipped test creates actual symlinks to test import/output/database rejection.
Windows requires developer mode or suitable rights to create them; the application
itself needs neither. Linux CI exercises this test.

## Test map

| File | Covered behavior |
| --- | --- |
| `test_foundation.py` | Migrations, configuration, normalized identity, safe output names |
| `test_parsers.py` | SSH/Common/Combined variants, malformed/missing values, IPs, timezones, DST, controls |
| `test_ingestion.py` | Imports, duplicates/provenance, failures, encoding, oversized records, explicit paths |
| `test_detection.py` | Six rules, benign traffic, multiple rules, windows, ordering, duplicates, reruns, host isolation |
| `test_repository.py` | Persistence, status/history, evidence, filters/pages/aggregates, SQL strings, constraints, v1 upgrade |
| `test_cli_reporting_demo.py` | CLI workflows/exits, reports, deterministic labeled evaluation, overwrite protection |
| `test_dashboard.py` | Actual Streamlit widget navigation/filter/save operations against temporary databases |
| `test_security_and_edges.py` | Windows names/traversal/symlinks, global budgets, changed-input rollback, BOM, unrelated DBs, real CSV output, reopen/status |

## Evaluation method

`examples/ground-truth.json` assigns expected rule labels independently from the
engine to file/line and normalized ID. Seed 42, fixed timestamps, fictional accounts,
and reserved IPs make it reproducible. Evaluation refuses any different event set.

Per rule, expected positives are labeled event IDs and predicted positives are the
union of alert evidence IDs. Intersection gives TP, predicted-minus-expected FP,
expected-minus-predicted FN, and remaining events TN. Precision = TP/(TP+FP),
recall = TP/(TP+FN), F1 = 2TP/(2TP+FP+FN); undefined denominators yield null.

| Rule | TP evidence | FP evidence | FN evidence |
| --- | ---: | ---: | ---: |
| SSH brute force | 10 | 0 | 0 |
| SSH password spraying | 5 | 0 | 0 |
| SSH success after failures | 4 | 0 | 0 |
| HTTP enumeration | 4 | 0 | 0 |
| Suspicious HTTP request | 2 | 0 | 0 |
| HTTP authentication abuse | 5 | 0 | 0 |

Fixture precision/recall/F1 is 1 for these constructed scenarios. A negative-control
test removes predictions and checks nonzero false negatives. This validates the
metric computation and fixture behavior, not representative prevalence or real-world
accuracy. Shared IPs, retries, authorized scans, and missing context can cause false
positives; encoding variants, distributed activity, and invisible login outcomes
can cause false negatives. Boundary/normal-behavior tests cover additional cases.

## CI and remaining gaps

Actions run on pushes/PRs to main and manual dispatch: Windows/Linux Python 3.13,
hash-locked installation, Ruff, MyPy, coverage, installed CLI demo, wheel build,
and coverage XML artifacts. Actions use exact commit pins, read-only permissions,
and no persisted checkout credentials. See actual
[workflow outcomes](https://github.com/gig0d/security-log-analyzer/actions/workflows/ci.yml);
local success alone does not establish remote CI success.

Remaining gaps include exceptional resource paths, very large report pagination,
browser-rendered visual behavior, and representative real-log evaluation.
There is no throughput benchmark, stress certification, live attack test, or full
browser automation suite. All test payloads are inert local strings.
