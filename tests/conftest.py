"""Shared pytest fixtures for the test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from helpers import write_csv


@pytest.fixture
def input_csv(tmp_path: Path) -> Path:
    """Return a not-yet-materialized path for the input CSV."""
    return tmp_path / "input.csv"


@pytest.fixture
def output_csv(tmp_path: Path) -> Path:
    """Return a not-yet-materialized path for the output CSV."""
    return tmp_path / "output.csv"


@pytest.fixture(
    params=[
        pytest.param(
            "incident_id,file_name,data_owner\n"
            "INC-001,report.pdf,alice@example.com\n",
            id="missing-three-required-columns",
        ),
        pytest.param(
            "incident_id,file_name,data_owner,ssn,policy_action\n"
            "INC-001,report.pdf,alice@example.com,123-45-6789,block\n",
            id="missing-incident-notes-column",
        ),
        pytest.param(
            "foo,bar,baz\n1,2,3\n",
            id="completely-wrong-columns",
        ),
        pytest.param("", id="empty-file"),
    ]
)
def bad_input_csv(request: pytest.FixtureRequest, input_csv: Path) -> Path:
    """Materialize an input CSV that fails validation.

    Parametrized: each test using this fixture runs once per scenario.
    """
    write_csv(input_csv, request.param)
    return input_csv
