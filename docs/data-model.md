# Data model and migrations

SQLite is local, unencrypted storage. SQLAlchemy parameterizes values, enables
foreign keys per connection, and uses a five-second busy timeout. Event, source,
and alert identifiers are SHA-256 hex strings.

| Table | Purpose |
| --- | --- |
| `source_files` | Snapshot ID, canonical path, byte hash/size, import time |
| `ingestion_runs` | Execution start/end, RUNNING/COMPLETED/PARTIAL state, summary |
| `events` | Unique normalized ID, UTC time, source/IP/username, JSON payload |
| `source_records` | Composite snapshot/line key, event FK, sanitized raw record |
| `parse_failures` | Run/source FKs, line number, safe bounded failure reason |
| `detection_rules` | Rule ID and current definition JSON |
| `analysis_runs` | Detection time, complete settings, scope, analyzed/matched/new counts |
| `alerts` | Rule FK, severity, explanation, time span, IP/count/rationale, status |
| `alert_evidence` | Composite alert/event FKs |
| `status_history` | Previous/new status, change time, bounded note |
| `analysis_alerts` | Composite run/alert FKs, including repeated existing matches |
| `alert_aliases` | Former alert IDs linked to canonical IDs after identity upgrades |

```mermaid
erDiagram
    SOURCE_FILES ||--o{ SOURCE_RECORDS : contains
    EVENTS ||--o{ SOURCE_RECORDS : referenced_by
    SOURCE_FILES ||--o{ PARSE_FAILURES : contains
    INGESTION_RUNS ||--o{ PARSE_FAILURES : records
    DETECTION_RULES ||--o{ ALERTS : generates
    ALERTS ||--|{ ALERT_EVIDENCE : supports
    EVENTS ||--o{ ALERT_EVIDENCE : evidences
    ALERTS ||--|{ STATUS_HISTORY : records
    ANALYSIS_RUNS ||--o{ ANALYSIS_ALERTS : matches
    ALERTS ||--o{ ANALYSIS_ALERTS : observed_in
```

Events include UTC timestamp, source type, nullable host/IP/username, category,
action/outcome, nullable HTTP attributes, and safe parser metadata. Source references
are separate relationships. HTTP outcome is a protocol status classification
(`>=400` failure), not proof of an application's authentication outcome.
OpenSSH supplies a host; HTTP hosts require an optional explicit label.

Invalid IPs become null with bounded validation metadata and are excluded from
IP rules. Invalid/missing timestamps reject a record. Year/timezone assumptions
for syslog are recorded. Event IDs hash the complete normalized payload including
parser metadata, excluding import time and source path/line. Copies share one event
and retain multiple provenance references. SSH metadata includes observed source
port and sshd PID. Truly identical normalized same-time records still collapse.
Different parser assumptions can produce different events.

Source snapshot IDs include canonical path, content hash, parser selection, HTTP
host, and SSH year/timezone. Indexes cover event time/source/IP and IP-time,
alert rule/severity/status/time/IP, evidence, and provenance. Checks constrain alert
severity/status, positive count, and ordered times. Composite keys prevent duplicate
associations. Status/history changes commit together. Nonempty notes create history
entries even if the status is unchanged; an empty same-status save is a no-op.
Filters use inclusive UTC times and bounded pagination. Alert source-type filtering
uses associated evidence events. Report metadata records every filter and lists
table-specific search fields and filter scope.

## Migrations

`storage.migrate` uses `PRAGMA user_version` and version-controlled ORM table definitions:

| Version | Change |
| --- | --- |
| 0 → 1 | Source, ingestion, event, provenance, parse-failure tables |
| 1 → 2 | Rules, analyses, alerts, evidence, history, run matches |
| 2 → 3 | Reconstruct SSH identities and preserve historical alert aliases |

Opening v3 is idempotent. Integration tests retain v1/v2 data through upgrade and
then run detection. Future versions are refused. An existing version-zero database
containing user tables is refused to protect unrelated data. No dashboard feature
accepts arbitrary SQL. Back up a closed database before upgrading.

Version 3 creates `alert_aliases` and reconstructs old `openssh-v1` payloads from
stored safe source text using the original year/timezone assumptions. It never
opens the original files. Distinct ports/PIDs recover separate event IDs; provenance
and alert evidence are reassociated atomically. Existing alert states, history,
analysis associations, and first detection times are retained. Old alert IDs work
for detail, status/note updates, and incident export. Historical alerts retain one
deterministic representative per formerly collapsed event; newly recovered evidence
can generate additional alerts on the next analysis.

Missing or invalid legacy provenance aborts and rolls back the migration, including
schema/version changes. Restore a complete backup rather than discarding evidence.
Downgrades, automated retention, encryption, and distributed schema management
are not implemented. Richer migration tooling is unnecessary for these small
numbered transformations and may be introduced as the schema grows.
