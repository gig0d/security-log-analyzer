import csv
import io
import sqlite3
from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy import select
from test_detection import BASE, event, web
from test_parsers import http

import security_log_analyzer.ingestion as ingestion
from security_log_analyzer.config import Settings, load_settings
from security_log_analyzer.demo import synthetic_data
from security_log_analyzer.detection import detect
from security_log_analyzer.models import Severity, Status
from security_log_analyzer.parsers import ParseError, parse_line
from security_log_analyzer.reporting import build_report, report_csv
from security_log_analyzer.repository import (
    Filters,
    alert_page,
    analyze,
    event_page,
    statistics,
    update_status,
)
from security_log_analyzer.storage import AlertRow, IngestionRun, Store
from security_log_analyzer.utils import output_path


@pytest.mark.parametrize(
    "filename",
    [
        "../evil.csv",
        "..\\evil.csv",
        "C:\\evil.csv",
        "report.csv:stream",
        "CON",
        "nul.txt",
        "report.",
        "report ",
        "bad?.csv",
    ],
)
def test_windows_output_path_attacks(tmp_path, filename):
    with pytest.raises(ValueError):
        output_path(tmp_path, filename)


@pytest.mark.parametrize(
    "values",
    [
        {"ssh_timezone": "Unknown/Nowhere"},
        {"ssh_year": 0},
        {"window_seconds": True},
        {"window_seconds": "300"},
        {"sensitive_paths": ("relative",)},
        {"login_paths": ()},
        {"max_record_bytes": -1},
    ],
)
def test_bad_settings_are_explicit(values):
    with pytest.raises(ValueError):
        Settings(**values)


def test_oversized_config_and_invalid_filter_period(tmp_path):
    path = tmp_path / "config.toml"
    path.write_bytes(b"#" * 65537)
    with pytest.raises(ValueError):
        load_settings(path)
    with pytest.raises(ValueError):
        Filters(start=BASE, end=BASE - timedelta(seconds=1))
    with pytest.raises(ValueError):
        Filters(search="x" * 201)


def test_symlink_input_and_output_are_rejected(tmp_path):
    target = tmp_path / "original.log"
    target.write_text(http(), encoding="utf-8")
    link = tmp_path / "linked.log"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Creating symbolic links requires Windows developer mode or appropriate rights")
    with pytest.raises(ValueError):
        ingestion.discover(link, Settings())
    with pytest.raises(ValueError):
        ingestion.discover(tmp_path, Settings())
    with pytest.raises(ValueError):
        output_path(tmp_path, "linked.log")
    with pytest.raises(ValueError):
        Store(link)


def test_directory_enumeration_and_file_count_are_bounded(tmp_path):
    for i in range(3):
        (tmp_path / f"file{i}.log").write_text(http(), encoding="utf-8")
    with pytest.raises(ValueError, match="file limit"):
        ingestion.discover(tmp_path, Settings(max_files=2))
    with pytest.raises(ValueError, match="enumeration"):
        ingestion.discover(tmp_path, Settings(max_directory_entries=2))


def test_record_budget_rolls_back_only_the_current_file(tmp_path):
    store = Store(tmp_path / "test.db")
    path = tmp_path / "auth.log"
    path.write_text(http() + "\n" + http("/about") + "\n", encoding="utf-8")
    result = ingestion.ingest(store, path, Settings(max_ingestion_records=1))
    assert result.errors and result.inserted == 0
    assert event_page(store)[0] == 0
    with store.session() as session:
        assert session.scalar(select(IngestionRun.state)) == "PARTIAL"
    store.close()


def test_input_change_rolls_back_and_io_budget_is_enforced(tmp_path, monkeypatch):
    store = Store(tmp_path / "test.db")
    path = tmp_path / "access.log"
    path.write_text(http(), encoding="utf-8")
    digest = ingestion._digest

    def mutate(path, limit, budget):
        result = digest(path, limit, budget)
        path.write_text(http("/changed"), encoding="utf-8")
        return result

    monkeypatch.setattr(ingestion, "_digest", mutate)
    result = ingestion.ingest(store, path, Settings())
    assert "changed" in result.errors[0]
    assert event_page(store)[0] == 0
    with pytest.raises(ValueError, match="I/O"):
        digest(path, 10000, ingestion._Budget(1, 10))
    store.close()


def test_utf8_bom_and_control_characters_in_real_ingestion(tmp_path):
    store = Store(tmp_path / "test.db")
    path = tmp_path / "access.log"
    path.write_text(
        http(target="/<script>bad</script>", extra=' "-" "agent\x1b[31m"'), encoding="utf-8-sig"
    )
    assert ingestion.ingest(store, path, Settings()).inserted == 1
    row = event_page(store)[1][0]
    assert row["path"] == "/<script>bad</script>"
    assert "\x1b" not in row["user_agent"]
    store.close()


def test_newer_and_unrelated_databases_are_not_modified(tmp_path):
    newer = tmp_path / "future.db"
    with sqlite3.connect(newer) as connection:
        connection.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="newer"):
        Store(newer)
    unrelated = tmp_path / "unrelated.db"
    with sqlite3.connect(unrelated) as connection:
        connection.execute("CREATE TABLE private_data (id INTEGER)")
    with pytest.raises(ValueError, match="Unrecognized"):
        Store(unrelated)
    with sqlite3.connect(unrelated) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall() == [("private_data",)]


def test_every_rule_has_configurable_threshold_and_no_critical_by_default():
    settings = Settings(
        brute_force_failures=2,
        spray_accounts=2,
        success_failures=2,
        enumeration_requests=2,
        http_auth_failures=2,
    )
    records = [
        event(0, username="one"),
        event(1, username="two"),
        event(2),
        event(3),
        event(4, outcome="success"),
        web(5, "/admin"),
        web(6, "/.env"),
        web(7, "/login", 403),
        web(8, "/login", 403),
        web(9, "/?q=OR%201=1"),
    ]
    alerts = detect(records, settings)
    assert len({a.rule_id for a in alerts}) == 6
    assert all(a.severity != Severity.CRITICAL for a in alerts)


def test_windows_slide_across_clock_boundaries_and_privileged_account_metadata():
    records = [event(299 + i) for i in range(5)]
    assert detect(records, Settings())[0].rule_id == "SSH_BRUTE_FORCE"
    data = synthetic_data()
    root = next(parse_line(line, "ssh", Settings()) for line in data.ssh if "for root " in line)
    assert root.metadata["privileged_account"] is True


def test_distinct_account_window_eviction_and_ssh_account_success_boundary():
    settings = Settings(spray_accounts=2, brute_force_failures=10, success_failures=2)
    assert detect([event(0, username="one"), event(301, username="two")], settings) == []
    alerts = detect([event(0), event(1), event(300, outcome="success")], settings)
    assert alerts[0].rule_id == "SSH_SUCCESS_AFTER_FAILURE"
    assert detect([event(0), event(1), event(301.1, outcome="success")], settings) == []
    assert detect([replace(event(0), action="invalid_user") for _ in range(10)], Settings()) == []


def test_http_escaped_quotes_and_oversized_parser_input():
    parsed = parse_line(http(extra=' "-" "Agent \\"quoted\\""'), "http", Settings())
    assert parsed.user_agent == 'Agent \\"quoted\\"'
    with pytest.raises(ParseError, match="limit"):
        parse_line("X" * 100, "http", Settings(max_record_bytes=10))


def test_report_actual_csv_is_safe_and_status_survives_reopen(tmp_path):
    store = Store(tmp_path / "test.db")
    path = tmp_path / "access.log"
    path.write_text(
        "\n".join(
            http("/?q=union%20select%20x", stamp=f"15/Jan/2026:12:00:0{i} +0000") for i in range(2)
        ),
        encoding="utf-8",
    )
    ingestion.ingest(store, path, Settings())
    analyze(store, Settings())
    alert_id = alert_page(store)[1][0]["id"]
    with store.session.begin() as session:
        session.get(AlertRow, alert_id).title = "=HYPERLINK(1)"
    update_status(store, alert_id, Status.FALSE_POSITIVE)
    report = build_report(store, Filters(start=BASE, end=BASE))
    assert report["statistics"]["events"] == 1
    all_rows = list(csv.DictReader(io.StringIO(report_csv(build_report(store)))))
    assert any(row["title"] == "'=HYPERLINK(1)" for row in all_rows)
    store.close()
    reopened = Store(tmp_path / "test.db")
    assert alert_page(reopened, Filters(status=Status.FALSE_POSITIVE))[0] == 1
    assert statistics(reopened, Filters(source_ip="untrusted' OR 1=1"))["events"] == 0
    assert event_page(reopened)[0] == 2
    reopened.close()
