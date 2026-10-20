"""Parameterized queries, evidence persistence, and investigation workflow."""

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, cast

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from security_log_analyzer.config import Settings
from security_log_analyzer.detection import RULES, detect
from security_log_analyzer.models import Event, Severity, Status
from security_log_analyzer.storage import (
    AlertAlias,
    AlertRow,
    AnalysisAlert,
    AnalysisRun,
    DetectionRuleRow,
    EventRow,
    Evidence,
    SourceFile,
    SourceRecord,
    StatusChange,
    Store,
)
from security_log_analyzer.utils import iso, safe_text, utc_now


@dataclass(frozen=True)
class Filters:
    start: datetime | None = None
    end: datetime | None = None
    source_ip: str | None = None
    source_type: str | None = None
    severity: Severity | None = None
    status: Status | None = None
    rule_id: str | None = None
    search: str = ""

    def __post_init__(self) -> None:
        for stamp in (self.start, self.end):
            if stamp is not None:
                iso(stamp)
        if self.start and self.end and self.start > self.end:
            raise ValueError("Start time must not follow end time")
        if len(self.search) > 200:
            raise ValueError("Search text exceeds 200 characters")
        if self.source_type is not None and self.source_type not in {"ssh", "http"}:
            raise ValueError("Source type must be ssh or http")

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "start": iso(self.start) if self.start else None,
            "end": iso(self.end) if self.end else None,
            "severity": self.severity.value if self.severity else None,
            "status": self.status.value if self.status else None,
        }


DEFAULT_FILTERS = Filters()


def _page(limit: int, offset: int) -> None:
    if not 1 <= limit <= 500 or not 0 <= offset <= 10000000:
        raise ValueError("Pagination requires limit 1..500 and offset 0..10000000")


def _conditions(filters: Filters, alerts: bool = False) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    timestamp = AlertRow.first_seen if alerts else EventRow.timestamp
    ip = AlertRow.source_ip if alerts else EventRow.source_ip
    if filters.start:
        conditions.append(timestamp >= iso(filters.start))
    if filters.end:
        conditions.append(timestamp <= iso(filters.end))
    if filters.source_ip:
        conditions.append(ip == filters.source_ip)
    if alerts:
        if filters.source_type:
            conditions.append(
                AlertRow.id.in_(
                    select(Evidence.alert_id)
                    .join(EventRow, EventRow.id == Evidence.event_id)
                    .where(EventRow.source_type == filters.source_type)
                )
            )
        if filters.severity:
            conditions.append(AlertRow.severity == filters.severity.value)
        if filters.status:
            conditions.append(AlertRow.status == filters.status.value)
        if filters.rule_id:
            conditions.append(AlertRow.rule_id == filters.rule_id)
        if filters.search:
            conditions.append(
                or_(
                    AlertRow.title.icontains(filters.search, autoescape=True),
                    AlertRow.source_ip.icontains(filters.search, autoescape=True),
                    AlertRow.id.icontains(filters.search, autoescape=True),
                )
            )
    else:
        if filters.source_type:
            conditions.append(EventRow.source_type == filters.source_type)
        if filters.search:
            conditions.append(
                or_(
                    EventRow.username.icontains(filters.search, autoescape=True),
                    EventRow.payload["path"].as_string().icontains(filters.search, autoescape=True),
                    EventRow.id.icontains(filters.search, autoescape=True),
                )
            )
    return conditions


def event_page(
    store: Store, filters: Filters = DEFAULT_FILTERS, limit: int = 100, offset: int = 0
) -> tuple[int, list[dict[str, Any]]]:
    _page(limit, offset)
    conditions = _conditions(filters)
    with store.session() as session:
        total = session.scalar(select(func.count()).select_from(EventRow).where(*conditions)) or 0
        rows = session.scalars(
            select(EventRow)
            .where(*conditions)
            .order_by(EventRow.timestamp, EventRow.id)
            .limit(limit)
            .offset(offset)
        )
        return total, [{"id": row.id, **row.payload} for row in rows]


def alert_dict(row: AlertRow) -> dict[str, Any]:
    return {column.name: getattr(row, column.name) for column in AlertRow.__table__.columns}


def _find_alert(session: Session, alert_id: str) -> AlertRow:
    row = session.get(AlertRow, alert_id)
    if row is None:
        alias = session.get(AlertAlias, alert_id)
        if alias:
            row = session.get(AlertRow, alias.alert_id)
    if row is None:
        raise ValueError("Alert identifier was not found")
    return row


def alert_page(
    store: Store, filters: Filters = DEFAULT_FILTERS, limit: int = 100, offset: int = 0
) -> tuple[int, list[dict[str, Any]]]:
    _page(limit, offset)
    conditions = _conditions(filters, alerts=True)
    with store.session() as session:
        total = session.scalar(select(func.count()).select_from(AlertRow).where(*conditions)) or 0
        rows = session.scalars(
            select(AlertRow)
            .where(*conditions)
            .order_by(AlertRow.first_seen.desc(), AlertRow.id)
            .limit(limit)
            .offset(offset)
        )
        return total, [alert_dict(row) for row in rows]


def event_references(store: Store, event_id: str, limit: int = 100) -> dict[str, Any]:
    _page(limit, 0)
    with store.session() as session:
        query = (
            select(SourceFile.path, SourceRecord.line_number, SourceRecord.raw_text)
            .join(SourceRecord, SourceFile.id == SourceRecord.source_id)
            .where(SourceRecord.event_id == event_id)
        )
        total = (
            session.scalar(
                select(func.count())
                .select_from(SourceRecord)
                .where(SourceRecord.event_id == event_id)
            )
            or 0
        )
        rows = session.execute(
            query.order_by(SourceFile.path, SourceRecord.line_number).limit(limit)
        )
        return {"total": total, "records": [dict(row._mapping) for row in rows]}


def alert_detail(store: Store, alert_id: str, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    _page(limit, offset)
    with store.session() as session:
        row = _find_alert(session, alert_id)
        alert_id = row.id
        evidence = session.scalars(
            select(EventRow)
            .join(Evidence, EventRow.id == Evidence.event_id)
            .where(Evidence.alert_id == alert_id)
            .order_by(EventRow.timestamp, EventRow.id)
            .limit(limit)
            .offset(offset)
        )
        history = session.scalars(
            select(StatusChange)
            .where(StatusChange.alert_id == alert_id)
            .order_by(StatusChange.id.desc())
            .limit(100)
        )
        return {
            **alert_dict(row),
            "evidence": [{"id": e.id, **e.payload} for e in evidence],
            "evidence_offset": offset,
            "history": [
                {"from": h.previous_status, "to": h.status, "at": h.changed_at, "note": h.note}
                for h in history
            ],
        }


def update_status(store: Store, alert_id: str, status: Status, note: str = "") -> bool:
    if not isinstance(status, Status):
        raise ValueError("A valid investigation status is required")
    with store.session.begin() as session:
        row = _find_alert(session, alert_id)
        note = safe_text(note.strip(), 1000)
        if row.status != status.value or note:
            timestamp = iso(utc_now())
            session.add(
                StatusChange(
                    alert_id=row.id,
                    previous_status=row.status,
                    status=status.value,
                    changed_at=timestamp,
                    note=note,
                )
            )
            row.status = status.value
            row.updated_at = timestamp
            return True
    return False


def analyze(store: Store, settings: Settings, filters: Filters = DEFAULT_FILTERS) -> dict[str, int]:
    with store.session() as session:
        rows = list(
            session.scalars(
                select(EventRow)
                .where(*_conditions(filters))
                .order_by(EventRow.timestamp, EventRow.id)
                .limit(settings.max_analysis_events + 1)
            )
        )
    alerts = detect((Event.from_dict(row.payload) for row in rows), settings)
    timestamp = iso(utc_now())
    inserted = 0
    with store.session.begin() as session:
        for rule in RULES:
            session.merge(DetectionRuleRow(id=rule.id, definition=asdict(rule)))
        session.flush()
        run = AnalysisRun(
            detected_at=timestamp,
            configuration=settings.to_dict(),
            scope={
                "start": iso(filters.start) if filters.start else None,
                "end": iso(filters.end) if filters.end else None,
                "source_ip": filters.source_ip,
                "source_type": filters.source_type,
            },
            event_count=len(rows),
            matched_alerts=len(alerts),
            new_alerts=0,
        )
        session.add(run)
        session.flush()
        for alert in alerts:
            if session.get(AlertRow, alert.id) is None:
                payload = alert.to_dict()
                del payload["event_ids"]
                session.add(
                    AlertRow(**payload, status=Status.NEW.value, updated_at=alert.detected_at)
                )
                session.flush()
                session.add_all(Evidence(alert_id=alert.id, event_id=e) for e in alert.event_ids)
                session.add(
                    StatusChange(
                        alert_id=alert.id,
                        previous_status=None,
                        status=Status.NEW.value,
                        changed_at=alert.detected_at,
                        note="Created by detection analysis",
                    )
                )
                inserted += 1
            session.add(AnalysisAlert(analysis_id=run.id, alert_id=alert.id))
        run.new_alerts = inserted
    return {"events_analyzed": len(rows), "matched_alerts": len(alerts), "new_alerts": inserted}


def statistics(store: Store, filters: Filters = DEFAULT_FILTERS) -> dict[str, Any]:
    event_conditions = _conditions(filters)
    alert_conditions = _conditions(filters, alerts=True)
    with store.session() as session:

        def grouped(
            column: Any, model: Any, conditions: list[ColumnElement[bool]], top: int | None = None
        ) -> dict[str, int]:
            query = (
                select(column, func.count()).select_from(model).where(*conditions).group_by(column)
            )
            query = query.order_by(func.count().desc(), column) if top else query.order_by(column)
            if top:
                query = query.limit(top)
            return {str(key): cast(int, count) for key, count in session.execute(query)}

        return {
            "events": session.scalar(
                select(func.count()).select_from(EventRow).where(*event_conditions)
            )
            or 0,
            "alerts": session.scalar(
                select(func.count()).select_from(AlertRow).where(*alert_conditions)
            )
            or 0,
            "by_severity": grouped(AlertRow.severity, AlertRow, alert_conditions),
            "by_rule": grouped(AlertRow.rule_id, AlertRow, alert_conditions),
            "by_status": grouped(AlertRow.status, AlertRow, alert_conditions),
            "event_volume_utc_hour": grouped(
                func.substr(EventRow.timestamp, 1, 13), EventRow, event_conditions
            ),
            "alert_trend_utc_hour": grouped(
                func.substr(AlertRow.first_seen, 1, 13), AlertRow, alert_conditions
            ),
            "top_source_ips": grouped(AlertRow.source_ip, AlertRow, alert_conditions, top=10),
        }
