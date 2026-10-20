import csv
import io
import json

from typer.testing import CliRunner

from security_log_analyzer.cli import app
from security_log_analyzer.config import Settings
from security_log_analyzer.demo import evaluate, generate, synthetic_data
from security_log_analyzer.detection import detect
from security_log_analyzer.parsers import parse_line
from security_log_analyzer.reporting import build_report, csv_cell, report_csv
from security_log_analyzer.repository import alert_page
from security_log_analyzer.storage import Store

runner = CliRunner()


def test_synthetic_ground_truth_evaluation_and_negative_control():
    data = synthetic_data()
    assert data == synthetic_data()
    records = [parse_line(line, "auto", Settings()) for line in [*data.ssh, *data.http]]
    evaluation = evaluate(records, detect(records, Settings()), data.truth)
    assert (evaluation["events"], evaluation["alerts"]) == (53, 8)
    assert all(
        row["false_positive_evidence"] == row["false_negative_evidence"] == 0
        for row in evaluation["rules"].values()
    )
    degraded = evaluate(records, [], data.truth)
    assert degraded["rules"]["SSH_BRUTE_FORCE"]["false_negative_evidence"] == 10


def test_cli_demo_report_and_status(tmp_path):
    database = str(tmp_path / "demo.db")
    args = ["--db", database]
    result = runner.invoke(app, ["demo", *args, "--directory", str(tmp_path / "inputs"), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["detection"]["new_alerts"] == 8
    result = runner.invoke(app, ["detect", *args, "--json"])
    assert json.loads(result.stdout)["new_alerts"] == 0
    result = runner.invoke(app, ["alerts", *args, "--severity", "HIGH", "--json"])
    alert_id = json.loads(result.stdout)["alerts"][0]["id"]
    assert runner.invoke(app, ["status", alert_id, "RESOLVED", *args]).exit_code == 0
    result = runner.invoke(app, ["show", alert_id, *args, "--json"])
    assert json.loads(result.stdout)["status"] == "RESOLVED"
    result = runner.invoke(app, ["events", *args, "--limit", "2", "--json"])
    assert len(json.loads(result.stdout)["events"]) == 2
    result = runner.invoke(
        app,
        [
            "report",
            *args,
            "--alert-id",
            alert_id,
            "--output-dir",
            str(tmp_path / "exports"),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / "exports" / "security-report.json").read_text())
    assert report["incident"]["evidence"][0]["source_references"]["total"] == 1
    result = runner.invoke(app, ["demo", *args, "--directory", str(tmp_path / "inputs"), "--json"])
    assert json.loads(result.stdout)["detection"]["new_alerts"] == 0


def test_cli_validation_errors(tmp_path):
    args = ["--db", str(tmp_path / "test.db")]
    assert runner.invoke(app, ["--help"]).exit_code == 0
    assert runner.invoke(app, ["ingest", "missing.log", *args]).exit_code == 2
    assert runner.invoke(app, ["alerts", "--severity", "INVALID", *args]).exit_code == 2
    assert runner.invoke(app, ["events", "--limit", "501", *args]).exit_code == 2
    assert runner.invoke(app, ["detect", "--since", "2026-01-01", *args]).exit_code == 2
    assert runner.invoke(app, ["report", "--filename", "../escape", *args]).exit_code == 2
    path = tmp_path / "bad.log"
    path.write_text("bad", encoding="utf-8")
    assert runner.invoke(app, ["ingest", str(path), *args]).exit_code == 1
    assert runner.invoke(app, ["rules", "--json"]).exit_code == 0


def test_csv_formula_injection_and_untrusted_strings():
    for value in ("=HYPERLINK(1)", "+cmd", "-1", "@SUM(1)", "  =1"):
        assert csv_cell(value).startswith("'")
    assert "\n" not in csv_cell("first\nsecond")
    assert csv_cell("<script>alert(1)</script>") == "<script>alert(1)</script>"
    assert csv_cell("$(whoami); DROP TABLE events") == "$(whoami); DROP TABLE events"


def test_empty_report_and_demo_overwrite_protection(tmp_path):
    store = Store(tmp_path / "empty.db")
    report = build_report(store)
    assert list(csv.DictReader(io.StringIO(report_csv(report)))) == []
    assert alert_page(store)[0] == 0
    store.close()
    generate(tmp_path / "inputs")
    (tmp_path / "inputs" / "auth.log").write_text("existing", encoding="utf-8")
    result = runner.invoke(
        app, ["demo", "--db", str(tmp_path / "demo.db"), "--directory", str(tmp_path / "inputs")]
    )
    assert result.exit_code == 2
