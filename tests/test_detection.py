from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from security_log_analyzer.config import Settings
from security_log_analyzer.detection import detect, suspicious_indicators
from security_log_analyzer.models import Event

BASE = datetime(2026, 1, 15, 12, tzinfo=UTC)


def event(second=0, username="alice", outcome="failure", **kwargs):
    return Event(
        timestamp=BASE + timedelta(seconds=second),
        source_type="ssh",
        host="lab",
        source_ip="192.0.2.1",
        username=username,
        category="authentication",
        action="login",
        outcome=outcome,
        **kwargs,
    )


def web(second=0, path="/", status=200):
    return Event(
        timestamp=BASE + timedelta(seconds=second),
        source_type="http",
        host="web",
        source_ip="198.51.100.1",
        username=None,
        category="web",
        action="request",
        outcome="failure" if status >= 400 else "success",
        method="GET",
        path=path,
        status_code=status,
    )


def test_brute_force_and_single_account_not_spray():
    alerts = detect([event(i) for i in range(5)], Settings())
    assert [a.rule_id for a in alerts] == ["SSH_BRUTE_FORCE"]
    assert len(alerts[0].event_ids) == 5
    assert alerts[0].rationale["target_accounts"] == ["alice"]


def test_spray_can_match_brute_force_independently():
    alerts = detect([event(i, username=f"user{i}") for i in range(5)], Settings())
    assert {a.rule_id for a in alerts} == {"SSH_BRUTE_FORCE", "SSH_PASSWORD_SPRAY"}
    assert all(a.rationale["distinct_accounts"] == 5 for a in alerts)


def test_success_requires_same_account_host_ip_and_resets_history():
    failures = [event(i) for i in range(3)]
    assert detect([*failures, event(4, username="bob", outcome="success")], Settings()) == []
    alerts = detect(
        [*failures, event(4, outcome="success"), event(5, outcome="success")], Settings()
    )
    assert [a.rule_id for a in alerts] == ["SSH_SUCCESS_AFTER_FAILURE"]
    assert alerts[0].rationale["failure_count"] == 3
    assert len(alerts[0].event_ids) == 4
    assert detect([*failures, replace(event(4, outcome="success"), host="other")], Settings()) == []


def test_http_rules_and_endpoint_boundaries():
    paths = ["/.env", "/admin", "/.git/config", "/config"]
    events = [web(i, path=p, status=404) for i, p in enumerate(paths)]
    events += [web(10 + i, "/login", 401) for i in range(5)]
    events += [web(20, "/?q=union%20select%20name"), web(21, "/%252e%252e/etc/passwd")]
    alerts = detect(events, Settings())
    assert {a.rule_id for a in alerts} == {
        "HTTP_ENUMERATION",
        "HTTP_AUTH_ABUSE",
        "HTTP_SUSPICIOUS_REQUEST",
    }
    assert len([a for a in alerts if a.rule_id == "HTTP_SUSPICIOUS_REQUEST"]) == 2
    assert detect([web(i, "/login-logo", 401) for i in range(6)], Settings()) == []


def test_normal_activity_and_missing_ip_do_not_trigger():
    events = [event(0), event(1, outcome="success"), *[web(i, "/products") for i in range(10)]]
    assert detect(events, Settings()) == []
    assert detect([replace(event(i), source_ip=None) for i in range(6)], Settings()) == []


@pytest.mark.parametrize("last,expected", [(300, 1), (300.000001, 0)])
def test_inclusive_window_boundary(last, expected):
    assert (
        len(detect([event(0), event(1), event(2), event(3), event(last)], Settings())) == expected
    )


def test_order_duplicates_and_repeat_runs_are_deterministic():
    events = [event(i) for i in range(5)]
    first = detect(events, Settings(), BASE)
    second = detect([*reversed(events), *events], Settings(), BASE)
    assert first == second
    assert detect(events, Settings(), BASE + timedelta(hours=1))[0].id == first[0].id


def test_no_cross_host_correlation_and_resource_limit():
    assert detect([replace(event(i), host=f"host{i}") for i in range(5)], Settings()) == []
    with pytest.raises(ValueError, match="limit"):
        detect([event(i) for i in range(3)], Settings(max_analysis_events=2))


@pytest.mark.parametrize("target", ["/products?id=1", "/about", "/v1/users"])
def test_benign_targets(target):
    assert suspicious_indicators(target) == []
