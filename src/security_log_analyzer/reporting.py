"""Bounded self-contained reports and formula-safe CSV exports."""

import csv
import io
import json
from typing import Any

from sqlalchemy import func, select

from security_log_analyzer import __version__
from security_log_analyzer.repository import (
    DEFAULT_FILTERS,
    Filters,
    _conditions,
    alert_detail,
    alert_page,
    event_references,
    statistics,
)
from security_log_analyzer.storage import EventRow, Store
from security_log_analyzer.utils import iso, safe_text, utc_now


def csv_cell(value: Any) -> str:
    result = safe_text(str(value)) if value is not None else ""
    if result.lstrip().startswith(("=", "+", "-", "@")):
        result = "'" + result
    return result


def build_report(
    store: Store, filters: Filters = DEFAULT_FILTERS, alert_id: str | None = None
) -> dict[str, Any]:
    with store.session() as session:
        period = session.execute(
            select(func.min(EventRow.timestamp), func.max(EventRow.timestamp)).where(
                *_conditions(filters)
            )
        ).one()
    report: dict[str, Any] = {
        "schema_version": 1,
        "application_version": __version__,
        "generated_at": iso(utc_now()),
        "data_source": str(store.path),
        "period": {
            "requested_start": iso(filters.start) if filters.start else None,
            "requested_end": iso(filters.end) if filters.end else None,
            "observed_event_start": period[0],
            "observed_event_end": period[1],
            "semantics": "Inclusive UTC event timestamps and alert first-seen timestamps",
        },
        "filters": filters.to_dict(),
        "filter_scope": {
            "events": ["start", "end", "source_ip", "source_type", "search"],
            "alerts": [
                "start",
                "end",
                "source_ip",
                "source_type",
                "severity",
                "status",
                "rule_id",
                "search",
            ],
            "search_fields": {
                "events": ["id", "username", "path"],
                "alerts": ["id", "title", "source_ip"],
            },
            "source_type": "Alerts are matched through their evidence events",
        },
        "statistics": statistics(store, filters),
        "interpretation": "Alerts indicate suspicious evidence, not confirmed malicious activity.",
    }
    if alert_id:
        incident = alert_detail(store, alert_id, limit=500)
        count = incident["event_count"]
        if count > 10000:
            raise ValueError(
                "Incident exceeds 10000 evidence events; narrow analysis before export"
            )
        for offset in range(500, count, 500):
            incident["evidence"].extend(
                alert_detail(store, alert_id, limit=500, offset=offset)["evidence"]
            )
        for evidence in incident["evidence"]:
            evidence["source_references"] = event_references(store, evidence["id"])
        report["incident"] = incident
        report["incident_scope"] = (
            "All evidence for the selected alert, independent of summary period"
        )
    else:
        count, rows = alert_page(store, filters, limit=500)
        if count > 10000:
            raise ValueError("Report exceeds 10000 alerts; narrow the selected period")
        for offset in range(500, count, 500):
            rows.extend(alert_page(store, filters, limit=500, offset=offset)[1])
        report["alerts"] = rows
    return report


def report_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True) + "\n"


def report_csv(report: dict[str, Any]) -> str:
    stream = io.StringIO(newline="")
    fields = [
        "id",
        "rule_id",
        "title",
        "severity",
        "status",
        "source_ip",
        "event_count",
        "first_seen",
        "last_seen",
        "data_source",
        "report_start",
        "report_end",
        "report_filters",
    ]
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    rows = [report["incident"]] if "incident" in report else report["alerts"]
    for row in rows:
        values = {
            **row,
            "data_source": report["data_source"],
            "report_start": report["period"]["requested_start"]
            or report["period"]["observed_event_start"],
            "report_end": report["period"]["requested_end"]
            or report["period"]["observed_event_end"],
            "report_filters": json.dumps(report["filters"], sort_keys=True, ensure_ascii=True),
        }
        writer.writerow({field: csv_cell(values.get(field)) for field in fields})
    return stream.getvalue()
