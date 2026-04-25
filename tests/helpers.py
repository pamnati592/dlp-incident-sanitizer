"""Small, single-purpose helpers for the test suite.

Each helper does exactly one thing and has a name that says so.
"""

from __future__ import annotations

from pathlib import Path

from sanitizer import IncidentSanitizer

def write_csv(path: Path, content: str) -> None:
    """Write the given raw CSV text to ``path`` as UTF-8."""
    path.write_text(content, encoding="utf-8")


def read_csv(path: Path) -> str:
    """Read and return the UTF-8 text content of the CSV at ``path``."""
    return path.read_text(encoding="utf-8")


def run_full_pipeline(input_path: Path, output_path: Path) -> "IncidentSanitizer":  # noqa: F821
    """Run the full load → process → save pipeline and return the sanitizer. """

    sanitizer = IncidentSanitizer(input_path)
    sanitizer.process()
    sanitizer.save(output_path)
    return sanitizer
