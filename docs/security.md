# Security boundaries

This is a defensive educational analyzer for logs the operator is authorized to
read. It never automatically collects system logs, contacts request targets,
executes log content, blocks IPs, changes firewalls, or performs offensive scanning.
An alert expresses suspicious evidence and limitations, not verified compromise.

| Boundary | Implemented protection | Limit |
| --- | --- | --- |
| Log bytes | Strict UTF-8, optional initial BOM, bounded records/files/I/O, safe failure reasons | Unsupported formats fail; upstream records can be forged |
| Log/terminal injection | Control/format characters escaped in fields, references, notes, errors; JSON encoding | Physical newlines define records; authenticity is unknown |
| SQL injection | Bound ORM values, escaped literal search wildcards, fixed queries, FK/check constraints | Hostile local DB tampering is outside scope |
| HTML/script strings | Text/tables/JSON; no `unsafe_allow_html` | Rendering depends on Streamlit |
| CSV formulas | All fields sanitized; leading `=`, `+`, `-`, `@` after whitespace prefixed with apostrophe | CSV is not a lossless raw-log archive |
| Inputs | Explicit flat scope, `.log`/`.txt` whitelist, final symlink/junction rejection | Trusted linked ancestors can exist; this is not an OS sandbox |
| Outputs | Explicit directory, basename-only filename, Windows reserved-name and final symlink checks | Concurrent same-user filesystem races are outside scope |
| Persistence | Recognized schema/version checks and transactional writes | SQLite/reports are unencrypted and unauthenticated |
| Resources | File/record/directory limits, bounded queries/analysis/reports | Storage grows across imports; no automated retention |

The design applies validation, output encoding, and resource controls from the
[OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
HTTP formats follow the [Apache logging documentation](https://httpd.apache.org/docs/2.4/logs.html).
Windows timezone data follows [Python zoneinfo guidance](https://docs.python.org/3.13/library/zoneinfo.html).

Actual targets, usernames, agents, and raw references may still contain secrets or
personal data. Sanitization is not redaction. Import only authorized/minimized logs,
restrict directory access, and review reports before sharing. Source paths are
included in incident reports. Do not attach real logs/databases to public issues.

Keep private material in ignored `data/`, `local-logs/`, `exports/`, and `reports/`.
Environments, `.env` files, local databases/logs, caches, and report directories are
ignored. Only fictional deterministic `examples/` logs are intended for Git.
Gitignore does not replace staged-file review.

Streamlit binds to `127.0.0.1` with usage statistics disabled. Normal analyzer
import/detect/report/demo operations make no external requests. Dependency
installation, CI, and optional advisory audits require network access. Browser
runtime behavior remains a dependency concern.

There is no application authentication/authorization or isolation from local users
who can access files/processes. Public multiuser deployment requires those controls,
transport security, retention/audit policy, and a deployment review. Do not expose
the dashboard publicly using the local defaults.

Malformed records are counted without copying entire invalid inputs. Invalid IPs
are preserved as validation metadata and excluded from correlation. Missing/invalid
timestamps reject records. No unsafe deserialization or dynamic evaluation exists.
Changing files roll back their transaction; interruptions may leave RUNNING audit
rows. Reimport stable files to resume safely. Hashes support traceability, not
tamper-proof forensics.

Shared IPs, retries/scanners, unknown HTTP hosts, clock errors, incomplete logs,
and encoding/application differences affect confidence. HTTP failures returning
200/redirects are not detected by status-based rules. Record false positives and
tune configuration rather than treating synthetic metrics as production accuracy.
Report software problems with synthetic reproductions; use an appropriate private
channel for sensitive vulnerability details.
