"""DLP incident CSV sanitizer — load, transform, and save."""

from __future__ import annotations

import csv
from functools import wraps
from pathlib import Path

from config import (
    BAD_INPUT_MESSAGE,
    EMAIL_REGEX,
    KEYWORD_REGEX,
    REDACTED_PLACEHOLDER,
    REQUIRED_COLUMNS,
    SSN_REGEX,
)
from logger import get_logger

logger = get_logger(__name__)


def _requires_valid_state(func):
    """Skip the decorated method if ``self.is_valid`` is False."""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.is_valid:
            logger.warning("Operation skipped: invalid state")
            return
        return func(self, *args, **kwargs)
    return wrapper


class IncidentSanitizer:
    """Load a DLP incident CSV, sanitize its rows, and save the result.

    Lifecycle: ``__init__`` → :meth:`process` → :meth:`save`.
    Invalid input prints ``"Bad input"`` and leaves ``is_valid`` False.
    """

    def __init__(self, input_path: Path) -> None:
        """Read and validate the CSV at ``input_path``."""
        self.input_path = Path(input_path)
        self.columns: list[str] = []
        self.rows: list[dict[str, str]] = []
        self.is_valid = False
        self._load_data()

    @_requires_valid_state
    def process(self) -> None:
        """Apply the six sanitization rules to every loaded row in place."""
        logger.info(f"Processing {len(self.rows)} rows")
        for row in self.rows:
            self._apply_sanitization_to_row(row)

    @_requires_valid_state
    def save(self, output_path: Path) -> None:
        """Write the sanitized rows to ``output_path``."""
        self._write_csv(Path(output_path))

    def _load_data(self) -> None:
        """Read the input; print ``Bad input`` on any failure."""
        logger.info(f"Loading CSV from {self.input_path}")
        try:
            self._read_csv_content()
        except (FileNotFoundError, IsADirectoryError, PermissionError,
                csv.Error, UnicodeDecodeError) as err:
            logger.error(f"Cannot load {self.input_path}: {err}")
            print(BAD_INPUT_MESSAGE)
            return

        if not self._validate_columns(self.columns):
            logger.error(f"Missing required columns in {self.input_path}")
            print(BAD_INPUT_MESSAGE)
            return

        self.is_valid = True

    def _read_csv_content(self) -> None:
        """Stream the CSV, capture its header, and store rows."""
        with self.input_path.open("r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file, strict=True)
            self.columns = list(reader.fieldnames) if reader.fieldnames else []
            self.rows = [self._replace_none_with_empty(row) for row in reader]
            logger.info(f"Loaded {len(self.rows)} rows from {self.input_path}")

    def _apply_sanitization_to_row(self, row: dict) -> None:
        """Run all six rules on a single row."""
        row["incident_id"] = row["incident_id"].strip()
        row["file_name"] = row["file_name"].lower()
        row["data_owner"] = self._mask_email(row["data_owner"])
        row["ssn"] = self._mask_ssn(row["ssn"])
        row["policy_action"] = row["policy_action"].strip().upper()
        row["incident_notes"] = self._redact_keywords(row["incident_notes"])

    def _write_csv(self, path: Path) -> None:
        """Write ``self.rows`` to ``path``; print ``Bad input`` on I/O failure."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=self.columns)
                writer.writeheader()
                writer.writerows(self.rows)
            logger.info(f"Saved {len(self.rows)} rows to {path}")
        except OSError as err:
            logger.error(f"Cannot write to {path}: {err}")
            print(BAD_INPUT_MESSAGE)

    @staticmethod
    def _validate_columns(columns: list) -> bool:
        """True iff every required column is present in the header."""
        return all(col in columns for col in REQUIRED_COLUMNS)

    @staticmethod
    def _replace_none_with_empty(row: dict[str, str | None]) -> dict:
        """Replace any ``None`` values with empty strings."""
        return {key: ("" if value is None else value) for key, value in row.items()}

    @staticmethod
    def _mask_email(val: str) -> str:
        """Mask to ``x***@domain``; return unchanged if not a valid email."""
        if not EMAIL_REGEX.match(val):
            return val
        local, domain = val.split("@", 1)
        return f"{local[0]}***@{domain}"

    @staticmethod
    def _mask_ssn(val: str) -> str:
        """Mask to ``***-**-NNNN``; return unchanged if not a valid SSN."""
        if not SSN_REGEX.match(val):
            return val
        return f"***-**-{val[-4:]}"

    @staticmethod
    def _redact_keywords(val: str) -> str:
        """Replace sensitive keywords (case-insensitive) with ``[REDACTED]``."""
        return KEYWORD_REGEX.sub(REDACTED_PLACEHOLDER, val)
