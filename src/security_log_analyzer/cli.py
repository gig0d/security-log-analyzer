"""CLI entry points for local ingestion, investigation, reporting, and demonstration."""

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from sqlalchemy.exc import SQLAlchemyError

from security_log_analyzer.config import load_settings
from security_log_analyzer.demo import evaluate, generate
from security_log_analyzer.detection import RULES
from security_log_analyzer.detection import detect as detect_events
from security_log_analyzer.ingestion import ingest as ingest_path
from security_log_analyzer.models import Event, Severity, Status
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
from security_log_analyzer.storage import Store
from security_log_analyzer.utils import output_path, safe_text

app = typer.Typer(no_args_is_help=True, help="Local defensive SSH and HTTP security log analysis.")
console = Console(stderr=True)
Database = Annotated[Path, typer.Option("--db", help="Local SQLite database path.")]
Config = Annotated[Path | None, typer.Option("--config", help="Validated TOML settings file.")]
JsonOutput = Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON to stdout.")]
Since = Annotated[
    str | None, typer.Option("--since", help="Inclusive ISO timestamp with timezone.")
]
Until = Annotated[
    str | None, typer.Option("--until", help="Inclusive ISO timestamp with timezone.")
]


class Source(StrEnum):
    auto = "auto"
    ssh = "ssh"
    http = "http"


class ReportFormat(StrEnum):
    json = "json"
    csv = "csv"


def _filters(since: str | None, until: str | None, **values: Any) -> Filters:
    return Filters(
        start=datetime.fromisoformat(since) if since else None,
        end=datetime.fromisoformat(until) if until else None,
        **values,
    )


def _emit(value: Any, json_output: bool) -> None:
    rendered = json.dumps(value, indent=2, ensure_ascii=True)
    if json_output:
        typer.echo(rendered)
    else:
        Console().print_json(rendered)


@contextmanager
def _operation(database: Path) -> Iterator[Store]:
    store: Store | None = None
    try:
        store = Store(database)
        yield store
    except (OSError, ValueError, SQLAlchemyError) as exc:
        console.print("Error: " + safe_text(str(exc), 1000), markup=False)
        raise typer.Exit(2) from exc
    finally:
        if store:
            store.close()


@app.command()
def ingest(
    path: Annotated[Path, typer.Argument(help="Explicit UTF-8 .log/.txt file or flat directory.")],
    db: Database = Path("data/analyzer.db"),
    config: Config = None,
    source: Annotated[Source, typer.Option(help="Parser selection.")] = Source.auto,
    host: Annotated[str | None, typer.Option(help="Optional HTTP server identifier.")] = None,
    json_output: JsonOutput = False,
) -> None:
    """Import normalized events, retaining safe file/line provenance."""
    with _operation(db) as store:
        result = ingest_path(store, path, load_settings(config), source.value, host)
        _emit(asdict(result), json_output)
        if result.failures or result.errors:
            raise typer.Exit(1)


@app.command()
def detect(
    db: Database = Path("data/analyzer.db"),
    config: Config = None,
    since: Since = None,
    until: Until = None,
    json_output: JsonOutput = False,
) -> None:
    """Analyze stored events and persist deduplicated evidence-linked alerts."""
    with _operation(db) as store:
        _emit(analyze(store, load_settings(config), _filters(since, until)), json_output)


@app.command()
def alerts(
    db: Database = Path("data/analyzer.db"),
    severity: Severity | None = None,
    status: Status | None = None,
    rule: str | None = None,
    ip: str | None = None,
    search: str = "",
    since: Since = None,
    until: Until = None,
    limit: int = 100,
    offset: int = 0,
    json_output: JsonOutput = False,
) -> None:
    """Search and paginate security alerts by severity, rule, time, IP, and status."""
    with _operation(db) as store:
        total, rows = alert_page(
            store,
            _filters(
                since,
                until,
                severity=severity,
                status=status,
                rule_id=rule,
                source_ip=ip,
                search=search,
            ),
            limit,
            offset,
        )
        _emit({"total": total, "offset": offset, "alerts": rows}, json_output)


@app.command()
def events(
    db: Database = Path("data/analyzer.db"),
    source: str | None = None,
    ip: str | None = None,
    search: str = "",
    since: Since = None,
    until: Until = None,
    limit: int = 100,
    offset: int = 0,
    json_output: JsonOutput = False,
) -> None:
    """Search normalized events with bounded pagination."""
    with _operation(db) as store:
        total, rows = event_page(
            store,
            _filters(since, until, source_type=source, source_ip=ip, search=search),
            limit,
            offset,
        )
        _emit({"total": total, "offset": offset, "events": rows}, json_output)


@app.command()
def show(
    alert_id: str,
    db: Database = Path("data/analyzer.db"),
    limit: int = 100,
    offset: int = 0,
    json_output: JsonOutput = False,
) -> None:
    """Inspect an alert, its paginated evidence, provenance, and status history."""
    with _operation(db) as store:
        detail = alert_detail(store, alert_id, limit, offset)
        for evidence in detail["evidence"]:
            evidence["source_references"] = event_references(store, evidence["id"])
        _emit(detail, json_output)


@app.command("status")
def status_command(
    alert_id: str,
    status: Status,
    db: Database = Path("data/analyzer.db"),
    note: str = "",
    json_output: JsonOutput = False,
) -> None:
    """Persist a status change or a note, including notes with an unchanged status."""
    with _operation(db) as store:
        changed = update_status(store, alert_id, status, note)
        _emit({"alert_id": alert_id, "status": status.value, "changed": changed}, json_output)


@app.command()
def report(
    db: Database = Path("data/analyzer.db"),
    since: Since = None,
    until: Until = None,
    format: ReportFormat = ReportFormat.json,
    output_dir: Path = Path("reports"),
    filename: str | None = None,
    alert_id: str | None = None,
    json_output: JsonOutput = False,
    source: str | None = None,
    ip: str | None = None,
    severity: Severity | None = None,
    status: Status | None = None,
    rule: str | None = None,
    search: str = "",
) -> None:
    """Export a JSON summary/incident or a formula-safe CSV alert summary."""
    with _operation(db) as store:
        data = build_report(
            store,
            _filters(
                since,
                until,
                source_type=source,
                source_ip=ip,
                severity=severity,
                status=status,
                rule_id=rule,
                search=search,
            ),
            alert_id,
        )
        target = output_path(output_dir, filename or f"security-report.{format.value}")
        target.write_text(
            report_json(data) if format == ReportFormat.json else report_csv(data),
            encoding="utf-8",
            newline="",
        )
        _emit({"output": str(target), "format": format.value}, json_output)


@app.command()
def rules(config: Config = None, json_output: JsonOutput = False) -> None:
    """List rule definitions, limitations, and active threshold configuration."""
    try:
        settings = load_settings(config)
        _emit(
            {"configuration": settings.to_dict(), "rules": [asdict(rule) for rule in RULES]},
            json_output,
        )
    except (OSError, ValueError) as exc:
        console.print("Error: " + safe_text(str(exc)), markup=False)
        raise typer.Exit(2) from exc


@app.command()
def demo(
    db: Database = Path("data/demo.db"),
    directory: Path = Path("data/demo-inputs"),
    json_output: JsonOutput = False,
) -> None:
    """Generate labeled synthetic logs, ingest both sources, detect, and evaluate."""
    with _operation(db) as store:
        truth = generate(directory)
        settings = load_settings()
        imports = [
            asdict(ingest_path(store, directory / name, settings))
            for name in ("auth.log", "access.log")
        ]
        if any(item["failures"] or item["errors"] for item in imports):
            raise ValueError("Demo ingestion failed; inspect the ingestion summary")
        result = analyze(store, settings)
        _, rows = event_page(store, limit=500)
        records = [Event.from_dict({k: v for k, v in row.items() if k != "id"}) for row in rows]
        evaluation = evaluate(records, detect_events(records, settings), truth)
        _emit(
            {
                "database": str(store.path),
                "ingestion": imports,
                "detection": result,
                "evaluation": evaluation,
            },
            json_output,
        )


if __name__ == "__main__":
    app()
