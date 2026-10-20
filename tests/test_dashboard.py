from pathlib import Path

from streamlit.testing.v1 import AppTest
from typer.testing import CliRunner

from security_log_analyzer.cli import app
from security_log_analyzer.models import Status
from security_log_analyzer.repository import Filters, alert_page
from security_log_analyzer.storage import Store

ENTRY = Path(__file__).resolve().parents[1] / "dashboard.py"


def test_dashboard_navigation_filtering_and_status(tmp_path, monkeypatch):
    database = tmp_path / "demo.db"
    result = CliRunner().invoke(
        app, ["demo", "--db", str(database), "--directory", str(tmp_path / "inputs")]
    )
    assert result.exit_code == 0
    monkeypatch.setenv("SLA_DATABASE", str(database))
    dashboard = AppTest.from_file(str(ENTRY), default_timeout=30).run()
    assert not dashboard.exception
    assert [metric.value for metric in dashboard.metric][:2] == ["53", "8"]
    for page in ("Log explorer", "Detection rules", "Reports", "Security alerts"):
        dashboard.sidebar.radio[0].set_value(page).run()
        assert not dashboard.exception, page
        assert not dashboard.error, page
    dashboard.selectbox[0].set_value("HIGH").run()
    assert "4 matching alerts" in dashboard.caption[2].value or any(
        "4 matching alerts" in c.value for c in dashboard.caption
    )
    status_widget = next(
        item for item in dashboard.selectbox if item.label == "Set investigation status"
    )
    status_widget.set_value("INVESTIGATING")
    next(button for button in dashboard.button if button.label == "Save status").click().run()
    assert not dashboard.exception
    store = Store(database)
    assert alert_page(store, Filters(status=Status.INVESTIGATING))[0] == 1
    store.close()


def test_dashboard_empty_database_and_bad_period(tmp_path, monkeypatch):
    monkeypatch.setenv("SLA_DATABASE", str(tmp_path / "empty.db"))
    dashboard = AppTest.from_file(str(ENTRY), default_timeout=30).run()
    assert not dashboard.exception
    assert dashboard.metric[0].value == "0"
    next(item for item in dashboard.text_input if item.label == "Since (ISO timestamp)").set_value(
        "bad"
    ).run()
    assert dashboard.error
    assert not dashboard.exception
