"""Recover version-one SSH identities from stored provenance without rereading log files."""

from collections.abc import Mapping

from sqlalchemy import Table, delete, insert, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection

from security_log_analyzer.config import Settings
from security_log_analyzer.detection import alert_identifier
from security_log_analyzer.parsers import parse_line


def upgrade_ssh_identity(connection: Connection, tables: Mapping[str, Table]) -> None:
    events, records = tables["events"], tables["source_records"]
    evidence, alerts = tables["alert_evidence"], tables["alerts"]
    affected_alerts: set[str] = set()
    replacements: dict[str, str] = {}
    legacy = (events.c.source_type == "ssh") & (
        events.c.payload["metadata"]["parser"].as_string() == "openssh-v1"
    )
    while (
        batch := connection.execute(select(events).where(legacy).order_by(events.c.id).limit(500))
        .mappings()
        .all()
    ):
        for old in batch:
            metadata = old["payload"]["metadata"]
            settings = Settings(
                ssh_year=metadata.get("assumed_year"),
                ssh_timezone=metadata.get("assumed_timezone", "UTC"),
            )
            # Original safe records distinguish ports/PIDs that the old payload omitted.
            recovered: set[str] = set()
            for record in (
                connection.execute(select(records).where(records.c.event_id == old["id"]))
                .mappings()
                .all()
            ):
                parsed = parse_line(record["raw_text"], "ssh", settings)
                payload = parsed.to_dict()
                recovered.add(parsed.id)
                connection.execute(
                    sqlite_insert(events)
                    .values(
                        id=parsed.id,
                        timestamp=payload["timestamp"],
                        source_type=parsed.source_type,
                        source_ip=parsed.source_ip,
                        username=parsed.username,
                        payload=payload,
                    )
                    .on_conflict_do_nothing(index_elements=["id"])
                )
                connection.execute(
                    update(records)
                    .where(
                        records.c.source_id == record["source_id"],
                        records.c.line_number == record["line_number"],
                    )
                    .values(event_id=parsed.id)
                )
            if not recovered:
                raise ValueError("Cannot upgrade a legacy SSH event without stored provenance")
            representative = min(recovered)
            replacements[old["id"]] = representative
            alert_ids: list[str] = list(
                connection.scalars(
                    select(evidence.c.alert_id).where(evidence.c.event_id == old["id"])
                )
            )
            for alert_id in alert_ids:
                affected_alerts.add(alert_id)
                connection.execute(
                    sqlite_insert(evidence)
                    .values(alert_id=alert_id, event_id=representative)
                    .on_conflict_do_nothing()
                )
            connection.execute(delete(evidence).where(evidence.c.event_id == old["id"]))
            connection.execute(delete(events).where(events.c.id == old["id"]))

    for old_id in sorted(affected_alerts):
        old_alert = dict(
            connection.execute(select(alerts).where(alerts.c.id == old_id)).mappings().one()
        )
        ids: tuple[str, ...] = tuple(
            connection.scalars(
                select(events.c.id)
                .join(evidence, events.c.id == evidence.c.event_id)
                .where(evidence.c.alert_id == old_id)
                .order_by(events.c.timestamp, events.c.id)
            ).all()
        )
        rationale = {**old_alert["rationale"]}
        if "success_event" in rationale:
            rationale["success_event"] = replacements.get(
                rationale["success_event"], rationale["success_event"]
            )
        new_id = alert_identifier(
            old_alert["rule_id"], ids, rationale["threshold"], rationale["window_seconds"]
        )
        connection.execute(
            insert(alerts).values(**{**old_alert, "id": new_id, "rationale": rationale})
        )
        for name in ("alert_evidence", "status_history", "analysis_alerts", "alert_aliases"):
            table = tables[name]
            connection.execute(
                update(table).where(table.c.alert_id == old_id).values(alert_id=new_id)
            )
        connection.execute(insert(tables["alert_aliases"]).values(id=old_id, alert_id=new_id))
        connection.execute(delete(alerts).where(alerts.c.id == old_id))
