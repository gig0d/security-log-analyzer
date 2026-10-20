"""Run project quality checks without changing PowerShell execution policy."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = (
    ("ruff", "check", "."),
    ("ruff", "format", "--check", "."),
    ("mypy",),
    (
        "pytest",
        "--basetemp",
        ".tools/pytest-check",
        "--cov",
        "--cov-report=term-missing",
        "--cov-report=xml",
    ),
)

for check in CHECKS:
    subprocess.run([sys.executable, "-m", *check], cwd=ROOT, check=True)
