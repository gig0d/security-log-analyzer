"""Bounded parsers for OpenSSH syslog and HTTP Common/Combined formats."""

import re
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from zoneinfo import ZoneInfo

from security_log_analyzer.config import Settings
from security_log_analyzer.models import Event
from security_log_analyzer.utils import safe_text

MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}
SSH = re.compile(
    r"^(?P<stamp>\d{4}-\d\d-\d\dT\S+|[A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d) "
    r"(?P<host>\S+) sshd(?:-session)?\[(?P<pid>\d+)\]: (?P<body>.+)$"
)
LOGIN = re.compile(
    r"^(?P<result>Failed|Accepted) (?P<mechanism>password|publickey) for "
    r"(?P<invalid>invalid user )?(?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: .*)?$"
)
INVALID = re.compile(r"^Invalid user (?P<username>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?$")
QUOTED = r'"(?:[^"\\]|\\.)*"'
HTTP = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<username>\S+) \[(?P<stamp>[^\]]+)\] "
    rf"(?P<request>{QUOTED}) (?P<status>\d{{3}}) (?P<bytes>\d+|-)"
    rf"(?: (?P<referer>{QUOTED}) (?P<agent>{QUOTED}))?$"
)


class ParseError(ValueError):
    """A record does not match the documented supported format."""


def _ip(value: str, metadata: dict[str, Any]) -> str | None:
    try:
        return str(ip_address(value))
    except ValueError:
        metadata["invalid_source_ip"] = safe_text(value, 256)
        return None


def _ssh_time(value: str, settings: Settings) -> datetime:
    if value[0].isdigit():
        result = datetime.fromisoformat(value)
        if result.tzinfo is None:
            raise ParseError("SSH ISO timestamp requires an explicit timezone")
        return result.astimezone(UTC)
    if settings.ssh_year is None:
        raise ParseError("Yearless SSH syslog requires explicit ssh_year configuration")
    month, day, clock = value.split()
    hour, minute, second = map(int, clock.split(":"))
    naive = datetime(settings.ssh_year, MONTHS[month], int(day), hour, minute, second)
    zone = ZoneInfo(settings.ssh_timezone)
    result = naive.replace(tzinfo=zone)
    if result.utcoffset() != naive.replace(tzinfo=zone, fold=1).utcoffset():
        raise ParseError("Ambiguous or nonexistent local time; use an offset-bearing timestamp")
    if result.astimezone(UTC).astimezone(zone).replace(tzinfo=None) != naive:
        raise ParseError("Nonexistent local time")
    return result.astimezone(UTC)


def parse_ssh(line: str, settings: Settings) -> Event:
    match = SSH.fullmatch(line)
    if match is None:
        raise ParseError("Unsupported SSH record format")
    fields = LOGIN.fullmatch(match["body"])
    action = "login"
    if fields is None:
        fields = INVALID.fullmatch(match["body"])
        action = "invalid_user"
    if fields is None:
        raise ParseError("Unsupported OpenSSH event")
    # Keep observed connection/process attributes in identity, even at one-second precision.
    metadata: dict[str, Any] = {"parser": "openssh-v2", "process_id": match["pid"]}
    if fields["port"] is not None:
        port = fields["port"]
        if len(port) <= 5 and 0 < int(port) <= 65535:
            metadata["source_port"] = int(port)
        else:
            metadata["invalid_source_port"] = safe_text(port, 256)
    if action == "login":
        metadata["mechanism"] = fields["mechanism"]
        metadata["invalid_user"] = bool(fields["invalid"])
    metadata["privileged_account"] = fields["username"] == "root"
    if not match["stamp"][0].isdigit():
        metadata.update(assumed_year=settings.ssh_year, assumed_timezone=settings.ssh_timezone)
    try:
        timestamp = _ssh_time(match["stamp"], settings)
    except (ValueError, KeyError) as exc:
        raise ParseError(f"Invalid SSH timestamp: {exc}") from exc
    return Event(
        timestamp=timestamp,
        source_type="ssh",
        host=match["host"],
        source_ip=_ip(fields["ip"], metadata),
        username=fields["username"],
        category="authentication",
        action=action,
        outcome="success" if action == "login" and fields["result"] == "Accepted" else "failure",
        metadata=metadata,
    )


def parse_http(line: str, host: str | None = None) -> Event:
    match = HTTP.fullmatch(line)
    if match is None:
        raise ParseError("Unsupported HTTP Common/Combined record format")
    request = match["request"][1:-1]
    parts = request.split(" ")
    if len(parts) != 3 or not re.fullmatch(r"[A-Z]{1,20}", parts[0]):
        raise ParseError("HTTP request must include method, target, and protocol")
    if not re.fullmatch(r"HTTP/\d(?:\.\d)?", parts[2]) or not parts[1]:
        raise ParseError("Invalid HTTP request protocol or target")
    try:
        day, month, rest = match["stamp"].split("/", 2)
        numeric = f"{day}/{MONTHS[month]}/{rest}"
        timestamp = datetime.strptime(numeric, "%d/%m/%Y:%H:%M:%S %z").astimezone(UTC)
        status = int(match["status"])
        if not 100 <= status <= 599:
            raise ValueError("HTTP status outside 100..599")
    except (ValueError, KeyError) as exc:
        raise ParseError(f"Invalid HTTP timestamp or status: {exc}") from exc
    metadata: dict[str, Any] = {"parser": "http-clf-v1", "protocol": parts[2]}
    return Event(
        timestamp=timestamp,
        source_type="http",
        host=host,
        source_ip=_ip(match["ip"], metadata),
        username=None if match["username"] == "-" else match["username"],
        category="web",
        action="request",
        outcome="failure" if status >= 400 else "success",
        method=parts[0],
        path=parts[1],
        status_code=status,
        user_agent=match["agent"][1:-1] if match["agent"] else None,
        metadata=metadata,
    )


def parse_line(line: str, source_type: str, settings: Settings, host: str | None = None) -> Event:
    if len(line.encode("utf-8")) > settings.max_record_bytes:
        raise ParseError("Record exceeds configured byte limit")
    line = safe_text(line.rstrip("\r\n"), settings.max_record_bytes)
    if source_type == "auto":
        source_type = "ssh" if SSH.fullmatch(line) else "http"
    if source_type == "ssh":
        return parse_ssh(line, settings)
    if source_type == "http":
        return parse_http(line, safe_text(host, 256) if host else None)
    raise ParseError("Source must be auto, ssh, or http")
