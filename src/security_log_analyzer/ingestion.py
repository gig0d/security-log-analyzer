"""Explicit-location, streaming ingestion with transactional file snapshots."""

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from security_log_analyzer.config import Settings
from security_log_analyzer.parsers import ParseError, parse_line
from security_log_analyzer.storage import (
    EventRow,
    IngestionRun,
    ParseFailure,
    SourceFile,
    SourceRecord,
    Store,
)
from security_log_analyzer.utils import iso, safe_text, stable_id, utc_now


@dataclass
class IngestionSummary:
    files: int = 0
    records: int = 0
    inserted: int = 0
    duplicates: int = 0
    failures: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class _Budget:
    byte_limit: int
    record_limit: int
    bytes_read: int = 0
    records: int = 0

    def consume(self, size: int) -> None:
        self.bytes_read += size
        if self.bytes_read > self.byte_limit:
            raise ValueError("Ingestion exhausted the total I/O byte budget")

    def record(self) -> None:
        self.records += 1
        if self.records > self.record_limit:
            raise ValueError("Ingestion exceeds configured total record limit; file rolled back")


def discover(path: Path, settings: Settings) -> list[Path]:
    """Read only explicit files or immediate .log/.txt children; never recurse."""
    if path.is_symlink() or path.is_junction():
        raise ValueError("Symbolic links and junctions are not accepted as input")
    path = path.resolve(strict=True)
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = []
        for number, entry in enumerate(path.iterdir(), 1):
            if number > settings.max_directory_entries:
                raise ValueError("Directory exceeds configured entry enumeration limit")
            if entry.suffix.lower() in {".log", ".txt"} and entry.is_file():
                if entry.is_symlink() or entry.is_junction():
                    raise ValueError("Input directory contains linked files")
                files.append(entry)
                if len(files) > settings.max_files:
                    raise ValueError("Directory exceeds configured file limit")
    else:
        raise ValueError("Input must be a regular file or directory")
    files.sort()
    if not files:
        raise ValueError("No supported .log or .txt files found")
    total = 0
    for file in files:
        if file.suffix.lower() not in {".log", ".txt"}:
            raise ValueError("Only uncompressed UTF-8 .log and .txt files are supported")
        size = file.stat().st_size
        if size > settings.max_file_bytes:
            raise ValueError(f"Input exceeds per-file byte limit: {safe_text(file.name)}")
        total += size
    if total > settings.max_total_bytes:
        raise ValueError("Input exceeds total byte limit")
    return files


def _digest(path: Path, limit: int, budget: _Budget) -> str:
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as handle:
        while block := handle.read(65536):
            budget.consume(len(block))
            consumed += len(block)
            if consumed > limit:
                raise ValueError("File grew beyond configured byte limit")
            digest.update(block)
    return digest.hexdigest()


def _ingest_file(
    store: Store,
    path: Path,
    run_id: int,
    settings: Settings,
    source_type: str,
    host: str | None,
    budget: _Budget,
) -> IngestionSummary:
    summary = IngestionSummary(files=1)
    fingerprint = _digest(path, settings.max_file_bytes, budget)
    source_id = stable_id(
        [
            str(path),
            fingerprint,
            source_type,
            host,
            settings.ssh_year,
            settings.ssh_timezone,
        ]
    )
    with store.session.begin() as session:
        if session.get(SourceFile, source_id) is None:
            session.add(
                SourceFile(
                    id=source_id,
                    path=safe_text(str(path)),
                    sha256=fingerprint,
                    size=path.stat().st_size,
                    imported_at=iso(utc_now()),
                )
            )
            session.flush()
        consumed = 0
        line_number = 0
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while raw := handle.readline(settings.max_record_bytes + 1):
                line_number += 1
                budget.record()
                budget.consume(len(raw))
                summary.records += 1
                digest.update(raw)
                consumed += len(raw)
                oversized = len(raw) > settings.max_record_bytes
                if oversized and not raw.endswith(b"\n"):
                    while tail := handle.readline(settings.max_record_bytes + 1):
                        budget.consume(len(tail))
                        consumed += len(tail)
                        digest.update(tail)
                        if consumed > settings.max_file_bytes:
                            raise ValueError("File grew beyond configured byte limit")
                        if tail.endswith(b"\n"):
                            break
                if consumed > settings.max_file_bytes:
                    raise ValueError("File grew beyond configured byte limit")
                try:
                    if oversized:
                        raise ParseError("Record exceeds configured byte limit")
                    line = raw.decode("utf-8-sig" if line_number == 1 else "utf-8", errors="strict")
                    record = parse_line(line, source_type, settings, host)
                except (ParseError, UnicodeDecodeError) as exc:
                    summary.failures += 1
                    session.add(
                        ParseFailure(
                            run_id=run_id,
                            source_id=source_id,
                            line_number=line_number,
                            reason=safe_text(str(exc), 300),
                        )
                    )
                    continue
                event_id = record.id
                if session.get(EventRow, event_id) is None:
                    session.add(
                        EventRow(
                            id=event_id,
                            timestamp=record.to_dict()["timestamp"],
                            source_type=record.source_type,
                            source_ip=record.source_ip,
                            username=record.username,
                            payload=record.to_dict(),
                        )
                    )
                    session.flush()
                    summary.inserted += 1
                else:
                    summary.duplicates += 1
                if session.get(SourceRecord, (source_id, line_number)) is None:
                    session.add(
                        SourceRecord(
                            source_id=source_id,
                            line_number=line_number,
                            event_id=event_id,
                            raw_text=safe_text(line.rstrip()),
                        )
                    )
            if digest.hexdigest() != fingerprint:
                raise ValueError("Input changed during ingestion; file transaction rolled back")
    return summary


def ingest(
    store: Store,
    path: Path,
    settings: Settings,
    source_type: str = "auto",
    host: str | None = None,
) -> IngestionSummary:
    if source_type not in {"auto", "ssh", "http"}:
        raise ValueError("Source must be auto, ssh, or http")
    files = discover(path, settings)
    with store.session.begin() as session:
        run = IngestionRun(started_at=iso(utc_now()), state="RUNNING", summary={})
        session.add(run)
        session.flush()
        run_id = run.id
    summary = IngestionSummary()
    budget = _Budget(2 * settings.max_total_bytes, settings.max_ingestion_records)
    for file in files:
        try:
            result = _ingest_file(store, file, run_id, settings, source_type, host, budget)
            for name in ("files", "records", "inserted", "duplicates", "failures"):
                setattr(summary, name, getattr(summary, name) + getattr(result, name))
        except (OSError, ValueError) as exc:
            summary.errors.append(f"{safe_text(file.name)}: {safe_text(str(exc), 300)}")
            if budget.bytes_read > budget.byte_limit or budget.records > budget.record_limit:
                break
    with store.session.begin() as session:
        saved = session.get(IngestionRun, run_id)
        assert saved is not None
        saved.finished_at = iso(utc_now())
        saved.state = "PARTIAL" if summary.errors or summary.failures else "COMPLETED"
        saved.summary = asdict(summary)
    return summary
