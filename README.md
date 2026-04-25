# DLP Incident CSV Sanitizer

Loads a CSV file of DLP incidents, sanitizes sensitive fields, and saves a new CSV file while preserving the original row and column order.

## What The Project Does

- `incident_id`: trims leading and trailing whitespace.
- `file_name`: converts the value to lowercase.
- `data_owner`: masks email addresses so only the first character before `@` and the full domain remain visible.
- `ssn`: keeps only the last 4 digits visible when the format is valid.
- `policy_action`: trims whitespace and converts the value to uppercase.
- `incident_notes`: replaces `password`, `secret`, `token`, and `credential` with `[REDACTED]` in a case-insensitive way.

If required columns are missing or the input is invalid, the program prints exactly `Bad input` without crashing.

## Project Structure

```text
task2/
├── README.md
├── pyproject.toml
├── requirements.txt
├── src/
│   ├── config.py
│   ├── logger.py
│   └── sanitizer.py
└── tests/
    ├── conftest.py
    ├── helpers.py
    ├── e2e/
    │   └── test_pipeline.py
    └── unit/
        └── test_rules.py
```

- `src/sanitizer.py` contains the `IncidentSanitizer` class.
- `src/config.py` contains constants and regex patterns.
- `src/logger.py` defines basic logging.
- `tests/e2e/test_pipeline.py` contains end-to-end tests with `pytest`.
- `tests/unit/test_rules.py` contains unit tests for the sanitization rules.

## Setup

Requires Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## How To Run

Example usage from Python:

```python
from pathlib import Path
from sanitizer import IncidentSanitizer

sanitizer = IncidentSanitizer(Path("input.csv"))
sanitizer.process()
sanitizer.save(Path("output.csv"))
```

## How To Run Tests

Run all tests:

```bash
pytest
```

Run only end-to-end tests:

```bash
pytest -m e2e
```

Run only unit tests:

```bash
pytest -m unit
```

## Assumptions

- Input files are read as UTF-8. Files with a different encoding are treated as invalid input.
- Invalid email values remain unchanged.
- SSN values are changed only if they match the `XXX-XX-XXXX` format.
- Extra columns beyond the required six are preserved verbatim, in their original position.
- Required columns may appear in any order; the output preserves the input order.
- Truly blank lines between data rows are skipped (standard `csv.DictReader` behavior). They are not preserved in the output, since a row without an `incident_id` cannot be a sanitization target.
- The `Bad input` contract is interpreted broadly: it is printed not only when required columns are missing, but also when the input file cannot be opened (missing file, directory in place of a file, permission denied), when the file is not valid UTF-8, when the CSV is malformed, and when the output destination cannot be written. In every case the program exits gracefully without crashing.
- The constructor accepts both a `pathlib.Path` and a `str` for convenience; the value is normalized via `Path(input_path)` at the boundary.
