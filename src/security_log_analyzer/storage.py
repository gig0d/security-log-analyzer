"""SQLite ORM persistence with explicit, forward-only schema versions."""

from pathlib import Path
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, String, create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class SourceFile(Base):
    __tablename__ = "source_files"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    path: Mapped[str]
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int]
    imported_at: Mapped[str]


class IngestionRun(Base):
    __tablename__ = "ingestion_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[str]
    finished_at: Mapped[str | None]
    state: Mapped[str]
    summary: Mapped[dict[str, Any]] = mapped_column(JSON)


class EventRow(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[str] = mapped_column(index=True)
    source_type: Mapped[str] = mapped_column(index=True)
    source_ip: Mapped[str | None] = mapped_column(index=True)
    username: Mapped[str | None]
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    __table_args__ = (Index("ix_events_correlation", "source_ip", "timestamp"),)


class SourceRecord(Base):
    __tablename__ = "source_records"
    source_id: Mapped[str] = mapped_column(ForeignKey("source_files.id"), primary_key=True)
    line_number: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), index=True)
    raw_text: Mapped[str]


class ParseFailure(Base):
    __tablename__ = "parse_failures"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("ingestion_runs.id"))
    source_id: Mapped[str] = mapped_column(ForeignKey("source_files.id"))
    line_number: Mapped[int]
    reason: Mapped[str]


def _sqlite_setup(connection: Any, _: Any) -> None:
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def migrate(engine: Engine) -> None:
    """Apply numbered migrations; refuse unknown future schemas."""
    with engine.begin() as connection:
        version: int = connection.execute(text("PRAGMA user_version")).scalar_one()
        if version > 1:
            raise ValueError("Database schema is newer than this application")
        if version == 0:
            Base.metadata.create_all(connection)
            connection.execute(text("PRAGMA user_version=1"))


class Store:
    def __init__(self, path: Path) -> None:
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.engine = create_engine("sqlite:///" + path.as_posix())
        event.listen(self.engine, "connect", _sqlite_setup)
        migrate(self.engine)
        self.session = sessionmaker(self.engine, expire_on_commit=False)

    def close(self) -> None:
        self.engine.dispose()
