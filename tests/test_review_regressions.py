"""Regression cases found in the project review, including upgrade compatibility."""

import csv
import hashlib
import io
import json
import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text
from streamlit.testing.v1 import AppTest
from typer.testing import CliRunner

from security_log_analyzer.cli import app
from security_log_analyzer.config import Settings
from security_log_analyzer.demo import _legacy_truth, generate, synthetic_data
from security_log_analyzer.detection import detect, path_matches, suspicious_indicators
from security_log_analyzer.ingestion import ingest
from security_log_analyzer.models import Status
from security_log_analyzer.parsers import parse_line
from security_log_analyzer.reporting import build_report, report_csv, report_json
from security_log_analyzer.repository import (
    Filters,
    alert_detail,
    alert_page,
    analyze,
    event_page,
    event_references,
    update_status,
)
from security_log_analyzer.storage import EventRow, SourceFile, SourceRecord, Store
from security_log_analyzer.utils import iso, stable_id, utc_now


def ssh_line(second=0, port=42000, pid=123, success=False, syslog=False):
    stamp = f"Jan 15 06:00:0{second}" if syslog else f"2026-01-15T12:00:0{second}Z"
    action = "Accepted password" if success else "Failed password"
    return f"{stamp} lab sshd[{pid}]: {action} for user from 192.0.2.10 port {port} ssh2"


def legacy_store(tmp_path, lines, settings=None):
    """Build the actual former payload/provenance format, not a version-only mock."""
    settings = settings or Settings()
    store = Store(tmp_path / "legacy.db")
    path = tmp_path / "auth.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    fingerprint = hashlib.sha256(path.read_bytes()).hexdigest()
    source_id = stable_id(
        [str(path.resolve()), fingerprint, "auto", None, settings.ssh_year, settings.ssh_timezone]
    )
    with store.session.begin() as session:
        session.add(
            SourceFile(
                id=source_id,
                path=str(path.resolve()),
                sha256=fingerprint,
                size=path.stat().st_size,
                imported_at=iso(utc_now()),
            )
        )
        session.flush()
        for line_number, line in enumerate(lines, 1):
            current = parse_line(line, "ssh", settings)
            metadata = {
                key: value
                for key, value in current.metadata.items()
                if key not in {"source_port", "process_id"}
            }
            old = replace(current, metadata={**metadata, "parser": "openssh-v1"})
            if session.get(EventRow, old.id) is None:
                session.add(
                    EventRow(
                        id=old.id,
                        timestamp=old.to_dict()["timestamp"],
                        source_type="ssh",
                        source_ip=old.source_ip,
                        username=old.username,
                        payload=old.to_dict(),
                    )
                )
                session.flush()
            session.add(
                SourceRecord(
                    source_id=source_id, line_number=line_number, event_id=old.id, raw_text=line
                )
            )
    return store, path


def close_as_v2(store):
    path = store.path
    with store.engine.begin() as connection:
        connection.execute(text("DROP TABLE alert_aliases"))
        connection.execute(text("PRAGMA user_version=2"))
    store.close()
    return path


@pytest.mark.parametrize("vary", ["port", "pid"])
def test_distinct_same_second_attempts_are_detected_and_copies_deduplicate(tmp_path, vary):
    store = Store(tmp_path / "new.db")
    path = tmp_path / "auth.log"
    lines = [
        ssh_line(port=42000 + i if vary == "port" else 42000, pid=123 + i if vary == "pid" else 123)
        for i in range(5)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert ingest(store, path, Settings()).inserted == 5
    assert analyze(store, Settings())["new_alerts"] == 1
    assert alert_page(store)[1][0]["event_count"] == 5
    assert ingest(store, path, Settings()).duplicates == 5
    copied = tmp_path / "copied.log"
    copied.write_bytes(path.read_bytes())
    assert ingest(store, copied, Settings()).duplicates == 5
    assert event_page(store)[0] == 5
    assert analyze(store, Settings())["new_alerts"] == 0
    assert event_references(store, event_page(store)[1][0]["id"])["total"] == 2
    store.close()


def test_old_collapsed_events_are_recovered_without_rereading_files(tmp_path):
    store, path = legacy_store(tmp_path, [ssh_line(port=42000 + i) for i in range(5)])
    assert event_page(store)[0] == 1
    database = close_as_v2(store)
    original = path.read_text(encoding="utf-8")
    path.write_text("The original log has rotated", encoding="utf-8")
    upgraded = Store(database)
    assert event_page(upgraded)[0] == 5
    assert analyze(upgraded, Settings())["new_alerts"] == 1
    path.write_text(original, encoding="utf-8")
    assert ingest(upgraded, path, Settings()).duplicates == 5
    assert analyze(upgraded, Settings())["new_alerts"] == 0
    upgraded.close()


@pytest.mark.parametrize("syslog", [False, True])
def test_upgrade_preserves_alert_history_aliases_and_idempotency(tmp_path, syslog):
    settings = Settings(ssh_year=2026, ssh_timezone="America/Costa_Rica") if syslog else Settings()
    store, path = legacy_store(tmp_path, [ssh_line(i, syslog=syslog) for i in range(5)], settings)
    analyze(store, settings)
    old_id = alert_page(store)[1][0]["id"]
    update_status(store, old_id, Status.INVESTIGATING, "Preserve this investigation")
    original_detail = alert_detail(store, old_id)
    database = close_as_v2(store)
    upgraded = Store(database)
    detail = alert_detail(upgraded, old_id)
    assert detail["id"] != old_id
    assert detail["status"] == "INVESTIGATING"
    assert detail["history"] == original_detail["history"]
    assert detail["detected_at"] == original_detail["detected_at"]
    assert len(detail["evidence"]) == 5
    assert all(row["metadata"]["source_port"] == 42000 for row in detail["evidence"])
    assert analyze(upgraded, settings)["new_alerts"] == 0
    assert ingest(upgraded, path, settings).duplicates == 5
    assert update_status(upgraded, old_id, Status.RESOLVED, "Saved through old identifier")
    with upgraded.engine.connect() as connection:
        assert connection.execute(text("PRAGMA foreign_key_check")).all() == []
    upgraded.close()
    reopened = Store(database)
    assert alert_detail(reopened, old_id)["status"] == "RESOLVED"
    assert analyze(reopened, settings)["new_alerts"] == 0
    reopened.close()


def test_success_evidence_reference_is_updated_during_migration(tmp_path):
    store, _ = legacy_store(tmp_path, [ssh_line(i, success=i == 3) for i in range(4)])
    analyze(store, Settings())
    old_id = alert_page(store)[1][0]["id"]
    database = close_as_v2(store)
    upgraded = Store(database)
    detail = alert_detail(upgraded, old_id)
    success = next(row for row in detail["evidence"] if row["outcome"] == "success")
    assert detail["rationale"]["success_event"] == success["id"]
    assert analyze(upgraded, Settings())["new_alerts"] == 0
    upgraded.close()


def test_failed_migration_rolls_back_all_data_and_schema_changes(tmp_path):
    store, _ = legacy_store(tmp_path, [ssh_line(i) for i in range(2)])
    with store.session.begin() as session:
        session.scalar(
            select(SourceRecord).where(SourceRecord.line_number == 2)
        ).raw_text = "broken"
    before = {row["id"] for row in event_page(store)[1]}
    database = close_as_v2(store)
    with pytest.raises(ValueError, match="Unsupported"):
        Store(database)
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert {row[0] for row in connection.execute("SELECT id FROM events")} == before
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='alert_aliases'"
            ).fetchall()
            == []
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_migration_refuses_to_discard_events_with_missing_provenance(tmp_path):
    store, _ = legacy_store(tmp_path, [ssh_line()])
    with store.session.begin() as session:
        for record in session.scalars(select(SourceRecord)):
            session.delete(record)
    database = close_as_v2(store)
    with pytest.raises(ValueError, match="without stored provenance"):
        Store(database)
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 1
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


def test_missing_or_invalid_ssh_ports_do_not_fabricate_connection_data():
    invalid = parse_line(ssh_line(port=999999), "ssh", Settings())
    assert invalid.metadata["invalid_source_port"] == "999999"
    assert "source_port" not in invalid.metadata
    missing = parse_line(
        "2026-01-15T12:00:00Z lab sshd[123]: Invalid user guest from 192.0.2.1", "ssh", Settings()
    )
    assert missing.metadata["process_id"] == "123"
    assert "source_port" not in missing.metadata


@pytest.mark.parametrize(
    "target",
    [
        "/?q=UNION+SELECT+name",
        "/?q=UNION%20SELECT%20name",
        "/?q=UNION%2520SELECT%2520name",
        "/?q=1+OR+1%3D1",
    ],
)
def test_query_space_encodings_trigger_the_actual_rule(target):
    record = parse_line(
        f'198.51.100.2 - - [15/Jan/2026:12:00:00 +0000] "GET {target} HTTP/1.1" 400 0',
        "http",
        Settings(),
    )
    alerts = detect([record], Settings())
    assert len(alerts) == 1
    assert alerts[0].rationale["indicators"] == ["sql_probing"]


@pytest.mark.parametrize("target", ["/UNION+SELECT", "/?q=UNION%2BSELECT", "/?q=UNION%252BSELECT"])
def test_literal_path_or_encoded_query_plus_is_not_a_space(target):
    assert suspicious_indicators(target) == []


def test_decoded_path_delimiters_do_not_rewrite_url_structure():
    assert not path_matches("/admin%3Fpublic", ("/admin",))
    assert path_matches("/admin?next=%3Fpublic", ("/admin",))


@pytest.fixture
def demo_store(tmp_path):
    directory = tmp_path / "inputs"
    generate(directory)
    store = Store(tmp_path / "demo.db")
    ingest(store, directory, Settings())
    analyze(store, Settings())
    yield store
    store.close()


def test_same_status_note_survives_reopen_and_empty_save_is_noop(demo_store):
    alert_id = alert_page(demo_store)[1][0]["id"]
    before = alert_detail(demo_store, alert_id)
    assert update_status(demo_store, alert_id, Status.NEW, "Additional note\x1b[31m")
    assert not update_status(demo_store, alert_id, Status.NEW, "  \n\t ")
    reopened = Store(demo_store.path)
    detail = alert_detail(reopened, alert_id)
    assert len(detail["history"]) == len(before["history"]) + 1
    assert detail["history"][0]["from"] == detail["history"][0]["to"] == "NEW"
    assert detail["history"][0]["note"].startswith("Additional note")
    assert "\x1b" not in detail["history"][0]["note"]
    reopened.close()


@pytest.mark.parametrize("source,events,alerts", [("ssh", 22, 4), ("http", 31, 4)])
def test_reports_apply_source_to_alert_evidence_and_record_every_filter(
    demo_store, source, events, alerts
):
    filters = Filters(source_type=source, start=datetime(2026, 1, 15, tzinfo=UTC))
    report = json.loads(report_json(build_report(demo_store, filters)))
    assert report["statistics"]["events"] == events
    assert report["statistics"]["alerts"] == alerts
    assert report["filters"] == {
        "start": "2026-01-15T00:00:00+00:00",
        "end": None,
        "source_ip": None,
        "source_type": source,
        "severity": None,
        "status": None,
        "rule_id": None,
        "search": "",
    }
    assert all(row["rule_id"].startswith(source.upper()) for row in report["alerts"])
    assert "source_type" in report["filter_scope"]["alerts"]


def test_csv_and_json_include_search_and_table_specific_search_scope(demo_store):
    report = build_report(demo_store, Filters(source_type="http", search="Suspicious"))
    assert report["statistics"]["events"] == 0
    assert report["statistics"]["alerts"] == 2
    assert report["filters"]["search"] == "Suspicious"
    assert report["filter_scope"]["search_fields"]["events"] == ["id", "username", "path"]
    rows = list(csv.DictReader(io.StringIO(report_csv(report))))
    assert len(rows) == 2
    assert all(json.loads(row["report_filters"]) == report["filters"] for row in rows)


def test_cli_reports_expose_filters_and_cli_notes_accept_same_status(demo_store, tmp_path):
    runner = CliRunner()
    alert_id = alert_page(demo_store)[1][0]["id"]
    args = ["--db", str(demo_store.path)]
    result = runner.invoke(app, ["status", alert_id, "NEW", *args, "--note", "CLI note", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["changed"] is True
    assert alert_detail(demo_store, alert_id)["history"][0]["note"] == "CLI note"
    no_change = runner.invoke(app, ["status", alert_id, "NEW", *args, "--json"])
    assert json.loads(no_change.stdout)["changed"] is False
    result = runner.invoke(
        app,
        [
            "report",
            *args,
            "--source",
            "http",
            "--search",
            "Suspicious",
            "--severity",
            "MEDIUM",
            "--status",
            "NEW",
            "--rule",
            "HTTP_SUSPICIOUS_REQUEST",
            "--ip",
            "198.51.100.20",
            "--since",
            "2026-01-15T12:04:00Z",
            "--until",
            "2026-01-15T12:04:01Z",
            "--output-dir",
            str(tmp_path / "export"),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    output = json.loads((tmp_path / "export/security-report.json").read_text())
    assert output["filters"]["source_type"] == "http"
    assert output["filters"]["search"] == "Suspicious"
    assert output["filters"]["severity"] == "MEDIUM"
    assert output["filters"]["status"] == "NEW"
    assert output["filters"]["rule_id"] == "HTTP_SUSPICIOUS_REQUEST"
    assert output["filters"]["source_ip"] == "198.51.100.20"
    assert output["filters"]["start"] == "2026-01-15T12:04:00+00:00"
    assert output["filters"]["end"] == "2026-01-15T12:04:01+00:00"
    assert output["statistics"]["alerts"] == 2


def test_dashboard_saves_same_status_note_and_shows_report_filters(demo_store, monkeypatch):
    from pathlib import Path

    monkeypatch.setenv("SLA_DATABASE", str(demo_store.path))
    entry = Path(__file__).resolve().parents[1] / "dashboard.py"
    dashboard = AppTest.from_file(str(entry), default_timeout=30).run()
    dashboard.sidebar.radio[0].set_value("Security alerts").run()
    selected = next(item for item in dashboard.selectbox if item.label == "Inspect alert").value
    next(item for item in dashboard.text_area if item.label == "Investigation note").set_value(
        "UI note"
    )
    next(item for item in dashboard.button if item.label == "Save status").click().run()
    assert not dashboard.exception and not dashboard.error
    assert alert_detail(demo_store, selected)["history"][0]["note"] == "UI note"
    next(item for item in dashboard.text_area if item.label == "Investigation note").set_value("")
    next(item for item in dashboard.button if item.label == "Save status").click().run()
    assert any(item.value == "No changes to save." for item in dashboard.info)
    assert len(alert_detail(demo_store, selected)["history"]) == 2
    dashboard.sidebar.radio[0].set_value("Reports").run()
    next(item for item in dashboard.selectbox if item.label == "Report source").set_value(
        "http"
    ).run()
    data = json.loads(dashboard.json[0].value)
    assert data["filters"]["source_type"] == "http"
    assert (data["events"], data["alerts"]) == (31, 4)


def test_old_builtin_labels_upgrade_but_modified_inputs_are_protected(tmp_path):
    data = synthetic_data()
    generate(tmp_path)
    truth_path = tmp_path / "ground-truth.json"
    truth_path.write_text(json.dumps(_legacy_truth(data), indent=2) + "\n", encoding="utf-8")
    generate(tmp_path)
    assert json.loads(truth_path.read_text()) == data.truth
    unrelated = {**data.truth, "seed": 999}
    truth_path.write_text(json.dumps(unrelated), encoding="utf-8")
    with pytest.raises(ValueError, match="Refusing"):
        generate(tmp_path)
    assert json.loads(truth_path.read_text()) == unrelated
