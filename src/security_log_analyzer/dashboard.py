"""Local single-user Streamlit investigation interface backed by actual SQL queries."""

import os
from datetime import datetime
from pathlib import Path
from typing import Any

import plotly.graph_objects as go
import streamlit as st
from sqlalchemy.exc import SQLAlchemyError

from security_log_analyzer.config import Settings, load_settings
from security_log_analyzer.detection import RULES
from security_log_analyzer.models import Severity, Status
from security_log_analyzer.reporting import build_report, report_csv, report_json
from security_log_analyzer.repository import (
    Filters,
    alert_detail,
    alert_page,
    analyze,
    event_page,
    event_references,
    statistics,
    update_status,
)
from security_log_analyzer.storage import Store
from security_log_analyzer.utils import safe_text

COLORS = {"LOW": "#75aadb", "MEDIUM": "#f0c66c", "HIGH": "#f68c75", "CRITICAL": "#df708b"}
PAGE_SIZE = 50


def _chart(counts: dict[str, int], title: str, timeline: bool = False) -> None:
    figure = go.Figure()
    if timeline:
        figure.add_trace(
            go.Scatter(
                x=list(counts),
                y=list(counts.values()),
                mode="lines+markers",
                fill="tozeroy",
                line={"color": "#56d4bd", "width": 2},
            )
        )
    else:
        figure.add_trace(
            go.Bar(
                x=list(counts),
                y=list(counts.values()),
                marker_color=[COLORS.get(key, "#56d4bd") for key in counts],
            )
        )
    figure.update_layout(
        title=title,
        height=290,
        margin={"t": 45, "b": 30, "l": 15, "r": 15},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis={"rangemode": "tozero", "dtick": 1},
        font={"color": "#e7edf5"},
    )
    st.plotly_chart(figure, width="stretch")


def _table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    st.dataframe(
        [{key: row.get(key) for key in columns} for row in rows], hide_index=True, width="stretch"
    )


def overview(store: Store, filters: Filters) -> None:
    st.title("Security monitoring")
    st.caption("Evidence from local SSH and HTTP logs · All times in UTC")
    data = statistics(store, filters)
    columns = st.columns(4)
    columns[0].metric("Ingested events", data["events"])
    columns[1].metric("Security alerts", data["alerts"])
    columns[2].metric("High severity", data["by_severity"].get("HIGH", 0))
    columns[3].metric(
        "Open investigations", sum(data["by_status"].get(s, 0) for s in ("NEW", "INVESTIGATING"))
    )
    if not data["events"]:
        st.info("No events in this scope. Import logs with the CLI, or run the synthetic demo.")
    left, right = st.columns([2, 1])
    with left:
        _chart(data["event_volume_utc_hour"], "Event volume by UTC hour", timeline=True)
    with right:
        _chart({s: data["by_severity"].get(s, 0) for s in COLORS}, "Alerts by severity")
    left, right = st.columns(2)
    with left:
        _chart(data["alert_trend_utc_hour"], "Alert trend by UTC hour", timeline=True)
        _chart(data["top_source_ips"], "Top source IPs by alert count")
    with right:
        _chart(data["by_rule"], "Alerts by rule")
        st.subheader("Investigation queue")
        _table(
            [{"status": status, "alerts": count} for status, count in data["by_status"].items()],
            ["status", "alerts"],
        )
    st.caption("An alert indicates suspicious evidence and requires investigation.")


def security_alerts(store: Store, period: Filters) -> None:
    st.title("Security alerts")
    st.caption("Review a detection, inspect its evidence, and record an investigation decision.")
    columns = st.columns(4)
    severity = columns[0].selectbox("Severity", ["All", *[s.value for s in Severity]])
    status = columns[1].selectbox("Investigation status", ["All", *[s.value for s in Status]])
    rule = columns[2].selectbox("Rule", ["All", *[r.id for r in RULES]])
    ip = columns[3].text_input("Source IP", max_chars=64)
    search = st.text_input("Search alerts", max_chars=200)
    page = int(st.number_input("Alert page", min_value=1, max_value=200001, value=1, step=1))
    filters = Filters(
        start=period.start,
        end=period.end,
        source_ip=ip or None,
        search=search,
        severity=Severity(severity) if severity != "All" else None,
        status=Status(status) if status != "All" else None,
        rule_id=rule if rule != "All" else None,
    )
    total, rows = alert_page(store, filters, PAGE_SIZE, (page - 1) * PAGE_SIZE)
    st.caption(f"{total} matching alerts · Page {page} · Up to {PAGE_SIZE} rows per page")
    _table(rows, ["id", "severity", "rule_id", "status", "source_ip", "event_count", "first_seen"])
    if not rows:
        st.info("No alerts on this page. Adjust the filters or run detection.")
        return
    selected = st.selectbox("Inspect alert", [row["id"] for row in rows])
    evidence_page = int(
        st.number_input(
            "Evidence page",
            min_value=1,
            max_value=200001,
            value=1,
            step=1,
            key=f"evidence-{selected}",
        )
    )
    detail = alert_detail(store, selected, PAGE_SIZE, (evidence_page - 1) * PAGE_SIZE)
    st.subheader(detail["title"])
    st.text(detail["description"])
    st.caption(
        f"{detail['severity']} · {detail['status']} · {detail['event_count']} evidence events"
    )
    with st.expander("Detection rationale", expanded=True):
        st.json(detail["rationale"])
    with st.form("investigation"):
        choices = [s.value for s in Status]
        new_status = st.selectbox(
            "Set investigation status", choices, index=choices.index(detail["status"])
        )
        note = st.text_area(
            "Investigation note",
            max_chars=1000,
            help="Notes are saved even when the status stays unchanged.",
        )
        if st.form_submit_button("Save status"):
            if update_status(store, selected, Status(new_status), note):
                st.session_state["status_notice"] = "Investigation update saved."
                st.rerun()
            else:
                st.info("No changes to save.")
    st.subheader("Evidence events")
    _table(
        detail["evidence"],
        [
            "id",
            "timestamp",
            "source_type",
            "source_ip",
            "username",
            "path",
            "status_code",
            "outcome",
        ],
    )
    if detail["evidence"]:
        event_id = st.selectbox("Inspect evidence record", [e["id"] for e in detail["evidence"]])
        st.json(event_references(store, event_id))
    with st.expander("Investigation history (latest 100 entries)"):
        st.dataframe(detail["history"], hide_index=True, width="stretch")


def log_explorer(store: Store, period: Filters) -> None:
    st.title("Log explorer")
    st.caption("Search normalized records. Source content is displayed as data.")
    left, right = st.columns(2)
    source = left.selectbox("Source type", ["All", "ssh", "http"])
    ip = right.text_input("Event source IP", max_chars=64)
    search = st.text_input("Search path, username, or event ID", max_chars=200)
    page = int(st.number_input("Event page", min_value=1, max_value=200001, value=1, step=1))
    filters = Filters(
        start=period.start,
        end=period.end,
        source_type=source if source != "All" else None,
        source_ip=ip or None,
        search=search,
    )
    total, rows = event_page(store, filters, PAGE_SIZE, (page - 1) * PAGE_SIZE)
    st.caption(f"{total} matching events · Page {page} · Up to {PAGE_SIZE} rows per page")
    _table(
        rows,
        [
            "id",
            "timestamp",
            "source_type",
            "host",
            "source_ip",
            "username",
            "action",
            "outcome",
            "method",
            "path",
            "status_code",
        ],
    )
    if rows:
        selected = st.selectbox("Inspect event", [row["id"] for row in rows])
        st.json(next(row for row in rows if row["id"] == selected))
        with st.expander("Source references (first 100)"):
            st.json(event_references(store, selected))


def detection_rules(settings: Settings) -> None:
    st.title("Detection rules")
    st.caption(
        "Rules execute independently. Thresholds are read from the selected TOML configuration."
    )
    for rule in RULES:
        with st.expander(f"{rule.id} · {rule.title}"):
            st.text(rule.description)
            threshold = getattr(settings, rule.threshold_setting) if rule.threshold_setting else 1
            st.text(
                f"Severity: {rule.severity.value} | Threshold: {threshold} | "
                f"Window: {settings.window_seconds} seconds"
            )
            st.text("Limitation: " + rule.limitation)
    st.info(
        "HIGH: correlated SSH authentication risk. MEDIUM: HTTP probing or authentication "
        "indicators. No current rule assigns CRITICAL without stronger evidence."
    )
    with st.expander("Active configuration"):
        st.json(settings.to_dict())


def reports(store: Store, filters: Filters) -> None:
    st.title("Reports")
    st.caption("Export reproducible summaries or a self-contained incident with its evidence.")
    with st.expander("Report filters"):
        columns = st.columns(3)
        source = columns[0].selectbox("Report source", ["All", "ssh", "http"])
        severity = columns[1].selectbox("Report severity", ["All", *[s.value for s in Severity]])
        status = columns[2].selectbox("Report status", ["All", *[s.value for s in Status]])
        rule = st.selectbox("Report rule", ["All", *[r.id for r in RULES]])
        ip = st.text_input("Report source IP", max_chars=64)
        search = st.text_input("Report search", max_chars=200)
    filters = Filters(
        start=filters.start,
        end=filters.end,
        source_type=source if source != "All" else None,
        severity=Severity(severity) if severity != "All" else None,
        status=Status(status) if status != "All" else None,
        rule_id=rule if rule != "All" else None,
        source_ip=ip or None,
        search=search,
    )
    report_type = st.radio("Report scope", ["Summary", "Incident"], horizontal=True)
    alert_id = (
        st.text_input("Incident alert ID", max_chars=64) if report_type == "Incident" else None
    )
    if report_type == "Incident" and not alert_id:
        st.info("Copy an alert ID from Security alerts to prepare its incident report.")
        return
    data = build_report(store, filters, alert_id)
    st.json(
        {
            "data_source": data["data_source"],
            "period": data["period"],
            "filters": data["filters"],
            "filter_scope": data["filter_scope"],
            "events": data["statistics"]["events"],
            "alerts": data["statistics"]["alerts"],
        }
    )
    left, right = st.columns(2)
    left.download_button(
        "Download JSON report",
        data=report_json(data),
        file_name="security-report.json",
        mime="application/json",
    )
    right.download_button(
        "Download CSV summary",
        data=report_csv(data),
        file_name="security-report.csv",
        mime="text/csv",
    )
    st.caption(
        "CSV cells are protected against spreadsheet formula interpretation. "
        "Incident JSON includes evidence and source references; CSV contains an alert summary."
    )


def main() -> None:
    st.set_page_config(page_title="Security Log Analyzer", page_icon="🛡️", layout="wide")
    st.sidebar.title("Security Log Analyzer")
    st.sidebar.caption("LOCAL DEFENSIVE ANALYSIS")
    page = st.sidebar.radio(
        "Workspace", ["Overview", "Security alerts", "Log explorer", "Detection rules", "Reports"]
    )
    database = st.sidebar.text_input(
        "SQLite database", os.environ.get("SLA_DATABASE", "data/analyzer.db")
    )
    config = st.sidebar.text_input("Configuration file (optional)", "")
    with st.sidebar.expander("Time range (UTC)"):
        start = st.text_input("Since (ISO timestamp)", placeholder="2026-01-15T00:00:00Z")
        end = st.text_input("Until (ISO timestamp)", placeholder="2026-01-16T00:00:00Z")
    st.sidebar.caption("Local single-user educational tool. Alerts require investigation.")
    store: Store | None = None
    try:
        filters = Filters(
            start=datetime.fromisoformat(start) if start else None,
            end=datetime.fromisoformat(end) if end else None,
        )
        settings = load_settings(Path(config) if config else None)
        if not database.strip():
            raise ValueError("Select a local SQLite database path")
        store = Store(Path(database))
        if st.sidebar.button("Run detection", type="primary"):
            result = analyze(store, settings, filters)
            st.success(
                f"Analyzed {result['events_analyzed']} events. "
                f"Matched {result['matched_alerts']} alerts; {result['new_alerts']} new."
            )
        if "status_notice" in st.session_state:
            st.success(st.session_state.pop("status_notice"))
        if page == "Overview":
            overview(store, filters)
        elif page == "Security alerts":
            security_alerts(store, filters)
        elif page == "Log explorer":
            log_explorer(store, filters)
        elif page == "Detection rules":
            detection_rules(settings)
        elif page == "Reports":
            reports(store, filters)
    except (OSError, ValueError, SQLAlchemyError) as exc:
        st.error("Unable to complete the operation. " + safe_text(str(exc), 1000))
    finally:
        if store:
            store.close()
