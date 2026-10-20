import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from test_parsers import ssh

from security_log_analyzer.config import Settings
from security_log_analyzer.ingestion import ingest
from security_log_analyzer.models import Severity, Status
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
from security_log_analyzer.storage import AlertRow, Evidence, Store


@pytest.fixture
def populated(tmp_path):
    store = Store(tmp_path / "test.db")
    path = tmp_path / "auth.log"
    path.write_text(
        "\n".join(
            ssh("Failed password for user from 192.0.2.1 port 22 ssh2", f"2026-01-15T12:00:0{i}Z")
            for i in range(5)
        ),
        encoding="utf-8",
    )
    ingest(store, path, Settings())
    yield store
    store.close()


def test_alert_idempotency_and_status_persistence(populated):
    assert analyze(populated, Settings())["new_alerts"] == 1
    total, alerts = alert_page(populated)
    assert total == 1
    alert_id = alerts[0]["id"]
    update_status(populated, alert_id, Status.INVESTIGATING, "Reviewed\x1b[31m")
    assert analyze(populated, Settings())["new_alerts"] == 0
    detail = alert_detail(populated, alert_id)
    assert detail["status"] == "INVESTIGATING"
    assert len(detail["evidence"]) == 5 and len(detail["history"]) == 2
    assert "\x1b" not in detail["history"][0]["note"]
    assert event_references(populated, detail["evidence"][0]["id"])["total"] == 1
    assert len(alert_detail(populated, alert_id, limit=2, offset=2)["evidence"]) == 2


def test_filtering_aggregations_pagination_and_sql_strings(populated):
    analyze(populated, Settings())
    assert event_page(populated, limit=2, offset=4)[0] == 5
    assert len(event_page(populated, limit=2, offset=4)[1]) == 1
    assert alert_page(populated, Filters(severity=Severity.LOW))[0] == 0
    assert alert_page(populated, Filters(status=Status.NEW, source_ip="192.0.2.1"))[0] == 1
    assert event_page(populated, Filters(search="' OR 1=1;--"))[0] == 0
    assert event_page(populated, Filters(search="%"))[0] == 0
    stats = statistics(populated)
    assert (stats["events"], stats["alerts"]) == (5, 1)
    assert stats["top_source_ips"] == {"192.0.2.1": 1}
    with pytest.raises(ValueError):
        event_page(populated, limit=501)
    with pytest.raises(ValueError):
        alert_detail(populated, "missing")


def test_foreign_key_and_status_constraints(populated):
    with pytest.raises(IntegrityError), populated.session.begin() as session:
        session.add(Evidence(alert_id="missing", event_id="missing"))
    analyze(populated, Settings())
    with pytest.raises(IntegrityError), populated.session.begin() as session:
        row = session.scalar(select(AlertRow))
        row.status = "UNSUPPORTED"


def test_version_one_migrates_without_data_loss(populated):
    path = populated.path
    # Simulate a real v1 file by removing all v2 tables, retaining ingested events.
    with populated.engine.begin() as connection:
        for table in (
            "analysis_alerts",
            "status_history",
            "alert_evidence",
            "alerts",
            "analysis_runs",
            "detection_rules",
        ):
            connection.execute(text(f"DROP TABLE {table}"))
        connection.execute(text("PRAGMA user_version=1"))
    populated.close()
    upgraded = Store(path)
    assert event_page(upgraded)[0] == 5
    assert analyze(upgraded, Settings())["new_alerts"] == 1
    upgraded.close()
