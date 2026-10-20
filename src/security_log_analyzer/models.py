"""Normalized immutable domain records, independent of persistence and presentation."""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from ipaddress import ip_address
from typing import Any

from security_log_analyzer.utils import iso, stable_id


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Status(StrEnum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    source_type: str
    host: str | None
    source_ip: str | None
    username: str | None
    category: str
    action: str
    outcome: str
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        iso(self.timestamp)
        if self.source_type not in {"ssh", "http"}:
            raise ValueError("Unsupported event source type")
        if self.source_ip is not None:
            ip_address(self.source_ip)
        if self.status_code is not None and not 100 <= self.status_code <= 599:
            raise ValueError("Invalid HTTP status code")

    def to_dict(self) -> dict[str, Any]:
        values = asdict(self)
        values["timestamp"] = iso(self.timestamp)
        return values

    @property
    def id(self) -> str:
        return stable_id(self.to_dict())

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> "Event":
        return cls(**{**values, "timestamp": datetime.fromisoformat(values["timestamp"])})


@dataclass(frozen=True)
class Alert:
    id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    first_seen: str
    last_seen: str
    source_ip: str
    event_ids: tuple[str, ...]
    rationale: dict[str, Any]
    detected_at: str

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "event_count": len(self.event_ids)}
