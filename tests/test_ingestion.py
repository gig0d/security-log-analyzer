import pytest
from sqlalchemy import func, select
from test_parsers import http

from security_log_analyzer.config import Settings
from security_log_analyzer.ingestion import discover, ingest
from security_log_analyzer.storage import EventRow, IngestionRun, ParseFailure, SourceRecord, Store


def test_ingestion_duplicate_provenance_and_failures(tmp_path):
    store = Store(tmp_path / "test.db")
    path = tmp_path / "access.log"
    path.write_text(http() + "\nmalformed\n" + http() + "\n", encoding="utf-8")
    first = ingest(store, path, Settings())
    assert (first.inserted, first.duplicates, first.failures) == (1, 1, 1)
    second = ingest(store, path, Settings())
    assert (second.inserted, second.duplicates, second.failures) == (0, 2, 1)
    with store.session() as session:
        assert session.scalar(select(func.count()).select_from(EventRow)) == 1
        assert session.scalar(select(func.count()).select_from(SourceRecord)) == 2
        assert session.scalar(select(func.count()).select_from(ParseFailure)) == 2
        assert session.scalar(select(IngestionRun.state)) == "PARTIAL"
    store.close()


def test_large_record_and_bad_encoding_are_bounded(tmp_path):
    store = Store(tmp_path / "test.db")
    path = tmp_path / "access.log"
    path.write_bytes(b"X" * 20000 + b"\n\xff\n" + http().encode() + b"\n")
    summary = ingest(store, path, Settings())
    assert (summary.inserted, summary.failures) == (1, 2)
    store.close()


def test_input_paths_and_limits(tmp_path):
    path = tmp_path / "secret.env"
    path.write_text("private", encoding="utf-8")
    with pytest.raises(ValueError):
        discover(path, Settings())
    with pytest.raises(FileNotFoundError):
        discover(tmp_path / "missing.log", Settings())
    path = tmp_path / "input.log"
    path.write_bytes(b"12345")
    with pytest.raises(ValueError):
        discover(path, Settings(max_file_bytes=4))
    with pytest.raises(ValueError):
        discover(tmp_path, Settings(max_total_bytes=4))
    sub = tmp_path / "unrequested"
    sub.mkdir()
    (sub / "nested.log").write_text("ignored", encoding="utf-8")
    assert discover(tmp_path, Settings()) == [path]
