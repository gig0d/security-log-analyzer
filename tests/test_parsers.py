from datetime import UTC, datetime

import pytest

from security_log_analyzer.config import Settings
from security_log_analyzer.parsers import ParseError, parse_line


def ssh(body, stamp="2026-01-15T12:00:00+00:00"):
    return f"{stamp} lab sshd[123]: {body}"


def http(target="/", ip="192.0.2.1", stamp="15/Jan/2026:12:00:00 +0000", extra=""):
    return f'{ip} - - [{stamp}] "GET {target} HTTP/1.1" 200 42{extra}'


@pytest.mark.parametrize(
    "body,outcome,action",
    [
        ("Failed password for invalid user root from 192.0.2.1 port 22 ssh2", "failure", "login"),
        ("Accepted publickey for alice from 2001:db8::1 port 22 ssh2", "success", "login"),
        ("Invalid user guest from 192.0.2.3 port 22", "failure", "invalid_user"),
    ],
)
def test_ssh_events(body, outcome, action):
    event = parse_line(ssh(body), "ssh", Settings())
    assert (event.outcome, event.action, event.host) == (outcome, action, "lab")


def test_yearless_syslog_requires_year():
    line = ssh("Failed password for user from 192.0.2.1 port 22 ssh2", "Jan 15 06:00:00")
    with pytest.raises(ParseError, match="year"):
        parse_line(line, "ssh", Settings())
    event = parse_line(line, "ssh", Settings(ssh_year=2026, ssh_timezone="America/Costa_Rica"))
    assert event.timestamp == datetime(2026, 1, 15, 12, tzinfo=UTC)
    assert event.metadata["assumed_year"] == 2026


@pytest.mark.parametrize("stamp", ["Nov  1 01:30:00", "Mar  8 02:30:00"])
def test_ambiguous_or_nonexistent_syslog_time(stamp):
    with pytest.raises(ParseError):
        parse_line(
            ssh("Invalid user user from 192.0.2.1", stamp),
            "ssh",
            Settings(ssh_year=2026, ssh_timezone="America/New_York"),
        )


def test_common_combined_offset_and_controls():
    event = parse_line(http(extra=' "-" "agent\x1b[31m"'), "http", Settings())
    assert "\x1b" not in event.user_agent
    assert event.username is None and event.host is None
    other = parse_line(http(stamp="15/Jan/2026:06:00:00 -0600"), "auto", Settings())
    assert event.timestamp == other.timestamp


def test_invalid_ip_preserves_event_without_fabrication():
    event = parse_line(http(ip="999.1.1.1"), "http", Settings())
    assert event.source_ip is None
    assert event.metadata["invalid_source_ip"] == "999.1.1.1"


@pytest.mark.parametrize(
    "line",
    [
        "",
        "garbage",
        http(stamp="32/Jan/2026:12:00:00 +0000"),
        ssh("Invalid user x from 192.0.2.1", "2026-01-15T12:00:00"),
        ssh("Invalid user x from 192.0.2.1", "2026-13-15T12:00:00Z"),
        '192.0.2.1 - - [15/Jan/2026:12:00:00 +0000] "-" 400 0',
        http().replace("200 42", "999 42"),
        http().replace("HTTP/1.1", "BOGUS"),
    ],
)
def test_malformed_records(line):
    with pytest.raises(ParseError):
        parse_line(line, "auto", Settings())
