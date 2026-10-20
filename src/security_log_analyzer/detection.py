"""Deterministic, evidence-based rules with bounded sliding time windows."""

import re
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import unquote, unquote_plus, urlsplit

from security_log_analyzer.config import Settings
from security_log_analyzer.models import Alert, Event, Severity
from security_log_analyzer.utils import iso, stable_id, utc_now


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    severity: Severity
    threshold_setting: str | None
    limitation: str


RULES = (
    Rule(
        "SSH_BRUTE_FORCE",
        "Repeated SSH authentication failures",
        "Multiple failed SSH logins from one source IP to one host.",
        Severity.HIGH,
        "brute_force_failures",
        "Shared NAT and legitimate retries may resemble brute force.",
    ),
    Rule(
        "SSH_PASSWORD_SPRAY",
        "SSH password spraying indicators",
        "Failed logins target multiple distinct accounts from one IP to one host.",
        Severity.HIGH,
        "spray_accounts",
        "No password values are available; account diversity is an indicator.",
    ),
    Rule(
        "SSH_SUCCESS_AFTER_FAILURE",
        "SSH success after repeated failures",
        "A successful login follows failures for the same IP, host, and username.",
        Severity.HIGH,
        "success_failures",
        "A legitimate user may recover from repeated mistyped credentials.",
    ),
    Rule(
        "HTTP_ENUMERATION",
        "Sensitive HTTP path enumeration",
        "Repeated requests target configured sensitive URL path prefixes.",
        Severity.MEDIUM,
        "enumeration_requests",
        "Authorized scanners and administrators can trigger this rule.",
    ),
    Rule(
        "HTTP_SUSPICIOUS_REQUEST",
        "Suspicious HTTP request indicator",
        "Request targets contain SQL probing or parent-directory traversal indicators.",
        Severity.MEDIUM,
        None,
        "An indicator does not demonstrate exploitability or success.",
    ),
    Rule(
        "HTTP_AUTH_ABUSE",
        "Repeated HTTP authentication failures",
        "Repeated 401/403 responses occur at configured authentication URL paths.",
        Severity.MEDIUM,
        "http_auth_failures",
        "Application-specific login failures returning 200 are not visible.",
    ),
)
RULE_BY_ID = {rule.id: rule for rule in RULES}
SQL_INDICATOR = re.compile(
    r"\bunion\s+(?:all\s+)?select\b|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1\b|"
    r"\bselect\s+.+?\s+from\b|\bsleep\s*\(",
    re.IGNORECASE,
)
TRAVERSAL = re.compile(r"(?:^|/)\.\.(?:/|$)")


def decoded_target(target: str) -> str:
    # A literal '+' represents a space only in the query, not in the URL path.
    path, separator, query = target[:16384].partition("?")
    decoded = unquote(unquote(path))
    if separator:
        decoded += "?" + unquote(unquote_plus(query))
    return decoded.replace("\\", "/").lower()


def target_path(target: str) -> str:
    try:
        path = urlsplit(target[:16384]).path
        return unquote(unquote(path)).replace("\\", "/").lower()
    except ValueError:
        return ""


def path_matches(target: str, prefixes: tuple[str, ...]) -> bool:
    path = target_path(target)
    return any(
        path == prefix.lower() or path.startswith(prefix.lower().rstrip("/") + "/")
        for prefix in prefixes
    )


def suspicious_indicators(target: str) -> list[str]:
    decoded = decoded_target(target)
    indicators = []
    if TRAVERSAL.search(decoded):
        indicators.append("parent_directory_traversal")
    if SQL_INDICATOR.search(decoded):
        indicators.append("sql_probing")
    return indicators


def alert_identifier(
    rule_id: str,
    event_ids: tuple[str, ...],
    threshold: int,
    window_seconds: int,
    sensitive_paths: tuple[str, ...] | None = None,
    login_paths: tuple[str, ...] | None = None,
) -> str:
    return stable_id(
        ["rules-v1", rule_id, event_ids, threshold, window_seconds, sensitive_paths, login_paths]
    )


def _alert(
    rule_id: str,
    events: list[Event],
    detected_at: str,
    settings: Settings,
    extra: dict[str, Any] | None = None,
) -> Alert:
    rule = RULE_BY_ID[rule_id]
    ids = tuple(event.id for event in events)
    threshold = getattr(settings, rule.threshold_setting) if rule.threshold_setting else 1
    rationale = {
        "threshold": threshold,
        "window_seconds": settings.window_seconds,
        "observed_events": len(events),
        "host": events[0].host,
        "target_accounts": sorted({e.username for e in events if e.username is not None}),
        "distinct_accounts": len({e.username for e in events if e.username is not None}),
        "limitation": rule.limitation,
        **(extra or {}),
    }
    assert events[0].source_ip is not None
    return Alert(
        id=alert_identifier(
            rule_id,
            ids,
            threshold,
            settings.window_seconds,
            settings.sensitive_paths if rule_id == "HTTP_ENUMERATION" else None,
            settings.login_paths if rule_id == "HTTP_AUTH_ABUSE" else None,
        ),
        rule_id=rule_id,
        title=rule.title,
        description=rule.description + " Suspicious evidence requires investigation.",
        severity=rule.severity,
        first_seen=iso(events[0].timestamp),
        last_seen=iso(events[-1].timestamp),
        source_ip=events[0].source_ip,
        event_ids=ids,
        rationale=rationale,
        detected_at=detected_at,
    )


def _windows(
    events: list[Event], threshold: int, seconds: int, distinct: bool = False
) -> Iterable[list[Event]]:
    """Emit and consume a window at its first threshold crossing; boundaries are inclusive."""
    window: deque[Event] = deque()
    accounts: Counter[str | None] = Counter()
    for event in events:
        while window and (event.timestamp - window[0].timestamp).total_seconds() > seconds:
            old = window.popleft()
            accounts[old.username] -= 1
            if accounts[old.username] == 0:
                del accounts[old.username]
        window.append(event)
        accounts[event.username] += 1
        count = len(accounts) if distinct else len(window)
        if count >= threshold:
            yield list(window)
            window.clear()
            accounts.clear()


def detect(
    events: Iterable[Event], settings: Settings, detected_at: datetime | None = None
) -> list[Alert]:
    """Sort and deduplicate a bounded dataset; independently evaluate every rule."""
    unique: dict[str, Event] = {}
    for count, event in enumerate(events, 1):
        if count > settings.max_analysis_events:
            raise ValueError("Analysis exceeds event limit; narrow the selected time range")
        unique[event.id] = event
    ordered = sorted(unique.values(), key=lambda e: (e.timestamp, e.id))
    timestamp = iso(detected_at or utc_now())
    groups: dict[tuple[str, str | None, str], list[Event]] = defaultdict(list)
    for event in ordered:
        if event.source_ip is not None:
            groups[(event.source_ip, event.host, event.source_type)].append(event)
    alerts: list[Alert] = []
    for group in groups.values():
        failures = [
            e
            for e in group
            if e.source_type == "ssh" and e.action == "login" and e.outcome == "failure"
        ]
        for rule_id, threshold, distinct in (
            ("SSH_BRUTE_FORCE", settings.brute_force_failures, False),
            ("SSH_PASSWORD_SPRAY", settings.spray_accounts, True),
        ):
            for window in _windows(failures, threshold, settings.window_seconds, distinct):
                alerts.append(_alert(rule_id, window, timestamp, settings))
        # Successful logins reset their own account's failure history.
        histories: dict[str, deque[Event]] = defaultdict(deque)
        for event in group:
            if event.source_type != "ssh" or event.action != "login" or event.username is None:
                continue
            history = histories[event.username]
            while (
                history
                and (event.timestamp - history[0].timestamp).total_seconds()
                > settings.window_seconds
            ):
                history.popleft()
            if event.outcome == "failure":
                history.append(event)
            elif event.outcome == "success":
                if len(history) >= settings.success_failures:
                    alerts.append(
                        _alert(
                            "SSH_SUCCESS_AFTER_FAILURE",
                            [*history, event],
                            timestamp,
                            settings,
                            {"failure_count": len(history), "success_event": event.id},
                        )
                    )
                history.clear()
        http_rules: tuple[tuple[str, int, Callable[[Event], bool]], ...] = (
            (
                "HTTP_ENUMERATION",
                settings.enumeration_requests,
                lambda e: path_matches(e.path or "", settings.sensitive_paths),
            ),
            (
                "HTTP_AUTH_ABUSE",
                settings.http_auth_failures,
                lambda e: (
                    e.status_code in {401, 403} and path_matches(e.path or "", settings.login_paths)
                ),
            ),
        )
        for rule_id, threshold, predicate in http_rules:
            matching = [e for e in group if e.source_type == "http" and predicate(e)]
            for window in _windows(matching, threshold, settings.window_seconds):
                alerts.append(_alert(rule_id, window, timestamp, settings))
        for event in group:
            if event.source_type == "http" and event.path:
                indicators = suspicious_indicators(event.path)
                if indicators:
                    alerts.append(
                        _alert(
                            "HTTP_SUSPICIOUS_REQUEST",
                            [event],
                            timestamp,
                            settings,
                            {"indicators": indicators},
                        )
                    )
    return sorted(alerts, key=lambda a: (a.first_seen, a.rule_id, a.id))
