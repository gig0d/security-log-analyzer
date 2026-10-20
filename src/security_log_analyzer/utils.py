"""Bounded, safe output and deterministic identifiers."""

import hashlib
import json
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def safe_text(value: str, limit: int = 16384) -> str:
    """Escape control and formatting characters, including terminal escape sequences."""
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char
        for char in value[:limit]
    )


def stable_id(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone")
    return value.astimezone(UTC).isoformat()


def output_path(directory: Path, filename: str) -> Path:
    """Confine generated filenames to an explicitly selected output directory."""
    if not filename or Path(filename).name != filename or any(c in filename for c in "/\\:"):
        raise ValueError("Output filename must be a plain filename without path components")
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / filename
    if target.is_symlink() or target.resolve().parent != directory:
        raise ValueError("Output must remain inside the selected directory")
    return target
