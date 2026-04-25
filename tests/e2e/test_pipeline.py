"""End-to-end tests for the full load → process → save pipeline."""

from __future__ import annotations
from pathlib import Path

import pytest

from helpers import read_csv, run_full_pipeline, write_csv
from sanitizer import IncidentSanitizer

pytestmark = pytest.mark.e2e


SPEC_HEADER = "incident_id,file_name,data_owner,ssn,policy_action,incident_notes\n"


@pytest.mark.parametrize(
    "input_rows,expected_rows",
    [
        pytest.param(
            " INC-001 ,Payroll_Report.xlsx,alice.smith@example.com,123-45-6789, block ,User shared password in email",
            "INC-001,payroll_report.xlsx,a***@example.com,***-**-6789,BLOCK,User shared [REDACTED] in email",
            id="trim-lowercase-mask-redact-password",
        ),
        pytest.param(
            "INC-002,Customer_List.csv,bob.jones@example.com,987-65-4321, allow ,Temporary token was exposed in attachment",
            "INC-002,customer_list.csv,b***@example.com,***-**-4321,ALLOW,Temporary [REDACTED] was exposed in attachment",
            id="redact-token-keyword",
        ),
        pytest.param(
            "INC-003,HR_Data.zip,invalid_email,111223333, review ,No secret found",
            "INC-003,hr_data.zip,invalid_email,111223333,REVIEW,No [REDACTED] found",
            id="invalid-email-and-ssn-stay-unchanged",
        ),
        pytest.param(
            " INC-001 ,Payroll_Report.xlsx,alice.smith@example.com,123-45-6789, block ,User shared password in email\n"
            "INC-002,Customer_List.csv,bob.jones@example.com,987-65-4321, allow ,Temporary token was exposed in attachment\n"
            "INC-003,HR_Data.zip,invalid_email,111223333, review ,No secret found",
            "INC-001,payroll_report.xlsx,a***@example.com,***-**-6789,BLOCK,User shared [REDACTED] in email\n"
            "INC-002,customer_list.csv,b***@example.com,***-**-4321,ALLOW,Temporary [REDACTED] was exposed in attachment\n"
            "INC-003,hr_data.zip,invalid_email,111223333,REVIEW,No [REDACTED] found",
            id="all-three-spec-rows-together",
        ),
        pytest.param(
            "INC-005,Report.PDF,,,,Token shared",
            "INC-005,report.pdf,,,,[REDACTED] shared",
            id="some-fields-empty-others-still-transform",
        ),
        pytest.param(
            "INC-006,,,,,",
            "INC-006,,,,,",
            id="all-fields-empty-except-incident-id",
        ),
    ],
)
def test_full_sanitization_cycle_on_spec_row(
    input_csv: Path,
    output_csv: Path,
    input_rows: str,
    expected_rows: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Each spec scenario round-trips to its expected sanitized form, no errors printed."""
    write_csv(input_csv, f"{SPEC_HEADER}{input_rows}\n")

    run_full_pipeline(input_csv, output_csv)

    assert read_csv(output_csv) == f"{SPEC_HEADER}{expected_rows}\n"
    assert capsys.readouterr().out == ""


def test_blank_lines_in_input_are_skipped(
    input_csv: Path, output_csv: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A truly blank line between rows must be skipped, not produce an empty row in the output."""
    write_csv(
        input_csv,
        f"{SPEC_HEADER}"
        "INC-001,a.csv,a@b.com,123-45-6789,block,n1\n"
        "\n"
        "INC-002,b.csv,b@c.com,987-65-4321,allow,n2\n",
    )

    run_full_pipeline(input_csv, output_csv)

    assert read_csv(output_csv) == (
        f"{SPEC_HEADER}"
        "INC-001,a.csv,a***@b.com,***-**-6789,BLOCK,n1\n"
        "INC-002,b.csv,b***@c.com,***-**-4321,ALLOW,n2\n"
    )
    assert capsys.readouterr().out == ""


def test_header_only_csv_produces_header_only_output(
    input_csv: Path, output_csv: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A CSV with valid header but zero data rows must round-trip cleanly."""
    write_csv(input_csv, SPEC_HEADER)

    run_full_pipeline(input_csv, output_csv)

    assert read_csv(output_csv) == SPEC_HEADER
    assert capsys.readouterr().out == ""


def test_extra_columns_pass_through_unchanged(
    input_csv: Path, output_csv: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Columns beyond the six required must be preserved verbatim in the output."""
    write_csv(
        input_csv,
        "incident_id,file_name,data_owner,ssn,policy_action,incident_notes,extra_col\n"
        "INC-001,Report.PDF,alice@example.com,123-45-6789, block ,User shared password,extra_value\n",
    )

    run_full_pipeline(input_csv, output_csv)

    assert read_csv(output_csv) == (
        "incident_id,file_name,data_owner,ssn,policy_action,incident_notes,extra_col\n"
        "INC-001,report.pdf,a***@example.com,***-**-6789,BLOCK,User shared [REDACTED],extra_value\n"
    )
    assert capsys.readouterr().out == ""


def test_columns_in_different_order_are_sanitized_correctly(
    input_csv: Path, output_csv: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Required columns in any order are processed correctly; output preserves input order."""
    write_csv(
        input_csv,
        "incident_notes,policy_action,ssn,data_owner,file_name,incident_id\n"
        "User shared password, block ,123-45-6789,alice@example.com,Report.PDF,INC-001\n",
    )

    run_full_pipeline(input_csv, output_csv)

    assert read_csv(output_csv) == (
        "incident_notes,policy_action,ssn,data_owner,file_name,incident_id\n"
        "User shared [REDACTED],BLOCK,***-**-6789,a***@example.com,report.pdf,INC-001\n"
    )
    assert capsys.readouterr().out == ""


def test_spec_quoted_input_is_handled_identically(
    input_csv: Path, output_csv: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The spec example uses double-quoted fields; csv.DictReader handles these
    transparently and the output must match the unquoted-input case verbatim."""
    write_csv(
        input_csv,
        f"{SPEC_HEADER}"
        '" INC-001 ","Payroll_Report.xlsx",alice.smith@example.com,123-45-6789," block ","User shared password in email"\n'
        '"INC-002","Customer_List.csv",bob.jones@example.com,987-65-4321," allow ","Temporary token was exposed in attachment"\n'
        '"INC-003","HR_Data.zip",invalid_email,111223333," review ","No secret found"\n',
    )

    run_full_pipeline(input_csv, output_csv)

    assert read_csv(output_csv) == (
        f"{SPEC_HEADER}"
        "INC-001,payroll_report.xlsx,a***@example.com,***-**-6789,BLOCK,User shared [REDACTED] in email\n"
        "INC-002,customer_list.csv,b***@example.com,***-**-4321,ALLOW,Temporary [REDACTED] was exposed in attachment\n"
        "INC-003,hr_data.zip,invalid_email,111223333,REVIEW,No [REDACTED] found\n"
    )
    assert capsys.readouterr().out == ""


def test_bad_input_prints_bad_input(
    bad_input_csv: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Any invalid CSV header must print 'Bad input' exactly once to stdout."""
    IncidentSanitizer(bad_input_csv)

    assert capsys.readouterr().out == "Bad input\n"


def test_bad_input_leaves_sanitizer_invalid(bad_input_csv: Path) -> None:
    """Any invalid CSV header must leave is_valid False."""
    assert IncidentSanitizer(bad_input_csv).is_valid is False


def test_bad_input_writes_no_output_file(
    bad_input_csv: Path, output_csv: Path
) -> None:
    """A bad-input save() must not create the output file."""
    sanitizer = IncidentSanitizer(bad_input_csv)
    sanitizer.save(output_csv)

    assert not output_csv.exists()


def test_missing_input_file_prints_bad_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A nonexistent input path must print 'Bad input' exactly once and not crash."""
    missing_path = tmp_path / "does_not_exist.csv"

    sanitizer = IncidentSanitizer(missing_path)

    assert capsys.readouterr().out == "Bad input\n"
    assert sanitizer.is_valid is False


def test_directory_input_prints_bad_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A directory passed as input must print 'Bad input' and leave the sanitizer invalid."""
    input_dir = tmp_path / "input_dir"
    input_dir.mkdir()

    sanitizer = IncidentSanitizer(input_dir)

    assert capsys.readouterr().out == "Bad input\n"
    assert sanitizer.is_valid is False


def test_unwritable_output_prints_bad_input(
    input_csv: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Writing to a path whose parent is not a directory must print 'Bad input' and not crash."""
    write_csv(
        input_csv,
        f"{SPEC_HEADER}"
        "INC-001,report.pdf,alice@example.com,123-45-6789,block,note\n",
    )
    sanitizer = IncidentSanitizer(input_csv)
    sanitizer.process()

    blocker = tmp_path / "blocker.txt"
    blocker.write_text("I am a file, not a directory")
    impossible_output = blocker / "out.csv"

    sanitizer.save(impossible_output)

    assert capsys.readouterr().out == "Bad input\n"
    assert not impossible_output.exists()


def test_badly_encoded_input_prints_bad_input(
    input_csv: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A non-UTF-8 file must print 'Bad input' and leave the sanitizer invalid."""
    input_csv.write_bytes(
        (
            f"{SPEC_HEADER}"
            "INC-001,report.pdf,alice@example.com,123-45-6789,block,note\n"
        ).encode("utf-16")
    )

    sanitizer = IncidentSanitizer(input_csv)

    assert capsys.readouterr().out == "Bad input\n"
    assert sanitizer.is_valid is False


def test_malformed_csv_prints_bad_input(
    input_csv: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Invalid CSV syntax must surface as bad input instead of crashing."""
    write_csv(
        input_csv,
        f"{SPEC_HEADER}"
        "INC-001,\"unterminated,alice@example.com,123-45-6789,block,note\n",
    )

    sanitizer = IncidentSanitizer(input_csv)

    assert capsys.readouterr().out == "Bad input\n"
    assert sanitizer.is_valid is False


def test_bad_input_process_and_save_are_no_ops(
    bad_input_csv: Path, output_csv: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """After the initial failure, process/save stay silent and do nothing."""
    sanitizer = IncidentSanitizer(bad_input_csv)
    first_output = capsys.readouterr().out

    sanitizer.process()
    sanitizer.save(output_csv)

    assert first_output == "Bad input\n"
    assert capsys.readouterr().out == ""
    assert not output_csv.exists()
