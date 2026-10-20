# Detection rules

The default window is **300 seconds**. Set thresholds in TOML; `rules --json`
shows effective settings and limitations. All rules run independently.

| Rule ID | Default trigger per source IP and host | Severity |
| --- | --- | --- |
| `SSH_BRUTE_FORCE` | 5 failed SSH login events within the window | HIGH |
| `SSH_PASSWORD_SPRAY` | Failed logins targeting 5 distinct usernames | HIGH |
| `SSH_SUCCESS_AFTER_FAILURE` | Success after 3 failures for the same username | HIGH |
| `HTTP_ENUMERATION` | 4 requests to sensitive path prefixes | MEDIUM |
| `HTTP_SUSPICIOUS_REQUEST` | One SQL probing or parent-directory traversal indicator | MEDIUM |
| `HTTP_AUTH_ABUSE` | 5 responses with 401/403 at configured login prefixes | MEDIUM |

HIGH represents correlated authentication risk requiring prompt review. MEDIUM
represents HTTP indicators with limited application context. LOW and CRITICAL are
valid storage/filter values; no current rule assigns them. Success after failures
does not establish compromise. Shared NAT, retries, administrators, and authorized
scanners can trigger alerts. HTTP login failures returning 200 or redirects are
not observable as failures using these status-based rules.

## Matching

Sensitive prefixes default to `/admin`, `/.env`, `/.git`, `/wp-admin`, `/config`.
Login prefixes default to `/login`, `/signin`, `/auth`. An exact path or slash
descendant matches; `/login/session` matches and `/login-logo` does not. Unknown
HTTP hosts remain null and share a correlation group; use `ingest --host` to
separate servers whose access-log format omits a hostname.

Targets are bounded, percent-decoded at most twice, lowercased, and have backslashes
normalized for matching. Literal `+` is interpreted as a space in queries only;
`%2B` remains a literal plus and path plus signs are preserved. URL structure is
split before decoding reserved path delimiters. SQL indicators include `UNION SELECT`, `OR 1=1`,
`SELECT ... FROM`, and `SLEEP(`. Traversal uses parent-directory segments.
These heuristics may match innocent content and miss novel/encoded attacks.
They never execute payloads, fetch targets, or interpret 200 as exploitation success.

SSH supports password/public-key success/failure and standalone invalid-user
notices. The notices are retained but excluded from failure thresholds, avoiding
double counting a notice and its failed-password record. `root` is tagged in event
metadata; privileged-account activity alone does not receive CRITICAL severity.

## Deterministic semantics

1. Deduplicate by normalized event ID. Sort by UTC timestamp then event ID.
   File order has no effect; equal-time records do not establish a reliable real-world sequence.
   SSH identities include observed source port and sshd PID so separate connections
   within one second remain distinct. Exact repeated normalized records still deduplicate.
2. Count/diversity rules use sliding windows per IP/host/source. Events exactly
   `window_seconds` apart are included; only older events are evicted.
3. Emit at the first threshold crossing, then consume that window for that rule.
   Continued activity needs another threshold's worth of evidence for a new alert.
   Counts describe the consumed window, not the source's lifetime total. Spraying
   can independently trigger brute force using the same evidence.
4. Success correlation keeps failures per IP/host/account, includes the success
   event as evidence, and clears that account's history on every success.
   `failure_count` differs from the total evidence `event_count`.
5. Alert IDs hash rule revision/ID, ordered evidence IDs, threshold/window, and
   relevant endpoint configuration. Detection time is excluded. Identical data and
   settings produce no duplicate persisted alerts and preserve status/history.
6. Late arrivals, added data, changed assumptions/settings, or a narrower scope
   can change evidence windows and generate new IDs. Existing alerts are retained
   rather than automatically deleted/merged. Scoped analysis has no lookback
   outside its selected period.

The schema-v3 migration reconstructs legacy SSH connection attributes and updates
evidence IDs. Historical alerts retain their original investigation state, history,
and detection time; old alert IDs remain resolvable aliases. If an old event hid
multiple connections, its historical alert keeps one deterministic representative
as evidence. All recovered connections participate in subsequent analysis, which
may produce additional alerts as with late-arriving data.

Each persisted alert contains its title, description, rule, severity, UTC first/last
observation, IP, count, rationale/limitations, detection time, and investigation
status. Evidence associations supply event IDs and source file/line references.

Review provenance, clock assumptions, shared IPs, account/endpoint ownership,
expected administrative activity, and surrounding records. Record NEW,
INVESTIGATING, RESOLVED, or FALSE_POSITIVE. No status triggers an automated response.
