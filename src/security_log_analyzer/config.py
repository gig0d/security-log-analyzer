"""Validated, reproducible resource limits and detection thresholds."""

import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


@dataclass(frozen=True)
class Settings:
    window_seconds: int = 300
    brute_force_failures: int = 5
    spray_accounts: int = 5
    success_failures: int = 3
    enumeration_requests: int = 4
    http_auth_failures: int = 5
    sensitive_paths: tuple[str, ...] = ("/admin", "/.env", "/.git", "/wp-admin", "/config")
    login_paths: tuple[str, ...] = ("/login", "/signin", "/auth")
    ssh_year: int | None = None
    ssh_timezone: str = "UTC"
    max_record_bytes: int = 16384
    max_file_bytes: int = 52428800
    max_total_bytes: int = 104857600
    max_files: int = 100
    max_analysis_events: int = 100000
    max_ingestion_records: int = 100000
    max_directory_entries: int = 1000

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if name in {"ssh_year", "ssh_timezone", "sensitive_paths", "login_paths"}:
                continue
            if type(value) is not int or not 1 <= value <= 100_000_000_000:
                raise ValueError(f"{name} must be a positive bounded integer")
        if self.ssh_year is not None and (
            type(self.ssh_year) is not int or not 1970 <= self.ssh_year <= 9998
        ):
            raise ValueError("ssh_year must be between 1970 and 9998")
        if not isinstance(self.ssh_timezone, str):
            raise ValueError("ssh_timezone must be an IANA timezone name")
        try:
            ZoneInfo(self.ssh_timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("ssh_timezone must name an available IANA timezone") from exc
        for name in ("sensitive_paths", "login_paths"):
            paths = getattr(self, name)
            if not isinstance(paths, tuple) or not paths or len(paths) > 100:
                raise ValueError(f"{name} must contain 1 to 100 paths")
            if any(not isinstance(p, str) or not p.startswith("/") or len(p) > 256 for p in paths):
                raise ValueError(f"{name} must contain bounded absolute URL paths")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_settings(path: Path | None = None) -> Settings:
    if path is None:
        return Settings()
    if path.stat().st_size > 65536:
        raise ValueError("Configuration exceeds 64 KiB")
    with path.open("rb") as handle:
        values = tomllib.load(handle)
    for name in ("sensitive_paths", "login_paths"):
        if name in values:
            values[name] = tuple(values[name])
    try:
        return Settings(**values)
    except TypeError as exc:
        raise ValueError(f"Unsupported configuration: {exc}") from exc
