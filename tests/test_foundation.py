from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from security_log_analyzer.config import Settings, load_settings
from security_log_analyzer.models import Event
from security_log_analyzer.storage import Store
from security_log_analyzer.utils import output_path, safe_text


def test_schema_migration_is_reproducible(tmp_path):
    path = tmp_path / "events.db"
    for _ in range(2):
        store = Store(path)
        with store.engine.connect() as connection:
            assert connection.execute(text("PRAGMA user_version")).scalar_one() == 3
            assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
        store.close()


def test_config_validation(tmp_path):
    with pytest.raises(ValueError):
        Settings(window_seconds=0)
    path = tmp_path / "config.toml"
    path.write_text("brute_force_failures = 7\n", encoding="utf-8")
    assert load_settings(path).brute_force_failures == 7
    path.write_text("unknown = 1", encoding="utf-8")
    with pytest.raises(ValueError):
        load_settings(path)


def test_event_identity_timezone_and_ip():
    values = dict(
        source_type="ssh",
        host="lab",
        source_ip="192.0.2.1",
        username="user",
        category="authentication",
        action="login",
        outcome="failure",
    )
    event = Event(timestamp=datetime(2026, 1, 1, tzinfo=UTC), **values)
    assert Event.from_dict(event.to_dict()).id == event.id
    with pytest.raises(ValueError):
        Event(timestamp=datetime(2026, 1, 1), **values)
    with pytest.raises(ValueError):
        Event(timestamp=datetime(2026, 1, 1, tzinfo=UTC), **{**values, "source_ip": "bad"})


def test_safe_outputs(tmp_path):
    assert "\x1b" not in safe_text("\x1b[31m\rhidden")
    with pytest.raises(ValueError):
        output_path(tmp_path, "../escape.csv")
    assert output_path(tmp_path, "report.json").parent == tmp_path
