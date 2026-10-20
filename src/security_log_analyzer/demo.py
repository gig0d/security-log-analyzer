"""Deterministic documentation-range logs and independently assigned scenario labels."""

import json
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_log_analyzer.config import Settings
from security_log_analyzer.detection import RULES
from security_log_analyzer.models import Alert, Event
from security_log_analyzer.parsers import parse_line
from security_log_analyzer.utils import output_path

REFERENCE = datetime(2026, 1, 15, 12, tzinfo=UTC)


@dataclass(frozen=True)
class DemoData:
    ssh: list[str]
    http: list[str]
    truth: dict[str, Any]


def synthetic_data() -> DemoData:
    randomizer = random.Random(42)
    lines: dict[str, list[str]] = {"ssh": [], "http": []}
    labels: list[dict[str, Any]] = []

    def add(source: str, line: str, scenario: str, rules: list[str]) -> None:
        lines[source].append(line)
        record = parse_line(line, source, Settings())
        labels.append(
            {
                "file": "auth.log" if source == "ssh" else "access.log",
                "line": len(lines[source]),
                "event_id": record.id,
                "scenario": scenario,
                "expected_rules": rules,
            }
        )

    def ssh(second: int, ip: str, user: str, success: bool = False) -> str:
        stamp = (REFERENCE + timedelta(seconds=second)).isoformat()
        result = "Accepted publickey" if success else "Failed password"
        return f"{stamp} lab-ssh sshd[100]: {result} for {user} from {ip} port 42000 ssh2"

    def http(second: int, ip: str, target: str, status: int = 200) -> str:
        stamp = (REFERENCE + timedelta(seconds=second)).strftime("%d/%m/%Y:%H:%M:%S +0000")
        # Numeric month is replaced explicitly, independent of the Windows locale.
        stamp = stamp.replace("/01/", "/Jan/")
        return f'{ip} - - [{stamp}] "GET {target} HTTP/1.1" {status} 128 "-" "SyntheticBrowser/1.0"'

    for index in range(8):
        add("ssh", ssh(index, f"203.0.113.{index + 1}", f"employee{index}", True), "normal_ssh", [])
    for index in range(20):
        target = randomizer.choice(("/", "/products", "/assets/style.css", "/about"))
        add("http", http(400 + index, f"203.0.113.{20 + index % 3}", target), "normal_http", [])
    for index in range(5):
        add("ssh", ssh(60 + index, "192.0.2.10", "root"), "ssh_brute_force", ["SSH_BRUTE_FORCE"])
        add(
            "ssh",
            ssh(120 + index, "192.0.2.20", f"analyst{index}"),
            "ssh_password_spray",
            ["SSH_BRUTE_FORCE", "SSH_PASSWORD_SPRAY"],
        )
    for index in range(4):
        add(
            "ssh",
            ssh(180 + index, "192.0.2.30", "operator", index == 3),
            "ssh_success_after_failure",
            ["SSH_SUCCESS_AFTER_FAILURE"],
        )
    for index, target in enumerate(("/.env", "/admin", "/.git/config", "/config")):
        add(
            "http",
            http(200 + index, "198.51.100.10", target, 404),
            "http_enumeration",
            ["HTTP_ENUMERATION"],
        )
    for index, target in enumerate(("/?id=1%20UNION%20SELECT%20name", "/%2e%2e/etc/passwd")):
        add(
            "http",
            http(240 + index, "198.51.100.20", target, 400),
            "http_suspicious_request",
            ["HTTP_SUSPICIOUS_REQUEST"],
        )
    for index in range(5):
        add(
            "http",
            http(260 + index, "198.51.100.30", "/login", 401),
            "http_auth_abuse",
            ["HTTP_AUTH_ABUSE"],
        )
    return DemoData(
        lines["ssh"],
        lines["http"],
        {"schema_version": 1, "seed": 42, "reference_utc": REFERENCE.isoformat(), "labels": labels},
    )


def generate(directory: Path) -> dict[str, Any]:
    data = synthetic_data()
    files = {
        "auth.log": "\n".join(data.ssh) + "\n",
        "access.log": "\n".join(data.http) + "\n",
        "ground-truth.json": json.dumps(data.truth, indent=2) + "\n",
    }
    paths = {name: output_path(directory, name) for name in files}
    for name, target in paths.items():
        if target.exists() and target.read_text(encoding="utf-8") != files[name]:
            raise ValueError(f"Refusing to overwrite different existing demo input: {name}")
    for name, target in paths.items():
        target.write_text(files[name], encoding="utf-8", newline="\n")
    return data.truth


def evaluate(events: list[Event], alerts: list[Alert], truth: dict[str, Any]) -> dict[str, Any]:
    actual_ids = {e.id for e in events}
    if actual_ids != {label["event_id"] for label in truth["labels"]}:
        raise ValueError("Evaluation requires exactly the labeled synthetic dataset")
    results: dict[str, Any] = {}
    for rule in RULES:
        expected = {
            label["event_id"] for label in truth["labels"] if rule.id in label["expected_rules"]
        }
        predicted = {
            event_id for alert in alerts if alert.rule_id == rule.id for event_id in alert.event_ids
        }
        tp, fp, fn = len(expected & predicted), len(predicted - expected), len(expected - predicted)
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        results[rule.id] = {
            "true_positive_evidence": tp,
            "false_positive_evidence": fp,
            "false_negative_evidence": fn,
            "true_negative_events": len(actual_ids - (expected | predicted)),
            "precision": precision,
            "recall": recall,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        }
    return {
        "method": "Per-rule event-evidence classification on fixed synthetic fixtures only",
        "events": len(actual_ids),
        "alerts": len(alerts),
        "rules": results,
        "limitation": "Fixture results do not measure real-world detection accuracy.",
    }
