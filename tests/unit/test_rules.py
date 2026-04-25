"""Unit tests for the six sanitization rules — built on Python's unittest.

Each rule is tested in isolation (no file I/O) by calling the static method
directly on the class. Every test follows AAA (Arrange / Act / Assert) and
makes exactly one assertion.

Usage:
    pytest                    # discovered automatically by pytest
    python -m unittest        # discovered automatically by unittest
"""

from __future__ import annotations

import unittest

import pytest

from sanitizer import IncidentSanitizer

pytestmark = pytest.mark.unit


class TestMaskEmail(unittest.TestCase):
    """Mask email: keep first char + full domain. Invalid → unchanged."""

    def test_simple_email_is_masked(self) -> None:
        self.assertEqual(
            IncidentSanitizer._mask_email("alice@example.com"),
            "a***@example.com",
        )

    def test_email_with_dots_in_local_part_is_masked(self) -> None:
        self.assertEqual(
            IncidentSanitizer._mask_email("alice.smith@example.com"),
            "a***@example.com",
        )

    def test_minimal_valid_email_is_masked(self) -> None:
        self.assertEqual(IncidentSanitizer._mask_email("x@y.z"), "x***@y.z")

    def test_string_without_at_sign_is_unchanged(self) -> None:
        self.assertEqual(
            IncidentSanitizer._mask_email("not-an-email"),
            "not-an-email",
        )

    def test_empty_local_part_is_invalid(self) -> None:
        self.assertEqual(IncidentSanitizer._mask_email("@nope.com"), "@nope.com")

    def test_empty_string_is_unchanged(self) -> None:
        self.assertEqual(IncidentSanitizer._mask_email(""), "")


class TestMaskSsn(unittest.TestCase):
    """Mask SSN: strict XXX-XX-XXXX only. Invalid format → unchanged."""

    def test_strict_format_is_masked(self) -> None:
        self.assertEqual(
            IncidentSanitizer._mask_ssn("123-45-6789"),
            "***-**-6789",
        )

    def test_bare_digits_are_unchanged(self) -> None:
        self.assertEqual(IncidentSanitizer._mask_ssn("111223333"), "111223333")

    def test_wrong_grouping_is_unchanged(self) -> None:
        self.assertEqual(
            IncidentSanitizer._mask_ssn("12-345-6789"),
            "12-345-6789",
        )

    def test_with_letters_is_unchanged(self) -> None:
        self.assertEqual(
            IncidentSanitizer._mask_ssn("abc-de-fghi"),
            "abc-de-fghi",
        )


class TestRedactKeywords(unittest.TestCase):
    """Word-bounded, case-insensitive redaction of sensitive keywords."""

    def test_single_keyword_is_redacted(self) -> None:
        self.assertEqual(
            IncidentSanitizer._redact_keywords("password"),
            "[REDACTED]",
        )

    def test_case_insensitive_match(self) -> None:
        self.assertEqual(
            IncidentSanitizer._redact_keywords("PaSSworD"),
            "[REDACTED]",
        )

    def test_keyword_with_trailing_punctuation(self) -> None:
        self.assertEqual(
            IncidentSanitizer._redact_keywords("password!"),
            "[REDACTED]!",
        )

    def test_keyword_with_surrounding_words(self) -> None:
        self.assertEqual(
            IncidentSanitizer._redact_keywords("User shared password in email"),
            "User shared [REDACTED] in email",
        )

    def test_multiple_keywords_in_one_string(self) -> None:
        self.assertEqual(
            IncidentSanitizer._redact_keywords("Token and Secret"),
            "[REDACTED] and [REDACTED]",
        )

    def test_substring_is_not_redacted(self) -> None:
        self.assertEqual(
            IncidentSanitizer._redact_keywords("tokenize"),
            "tokenize",
        )

    def test_text_with_no_keywords_is_unchanged(self) -> None:
        self.assertEqual(
            IncidentSanitizer._redact_keywords("nothing sensitive here"),
            "nothing sensitive here",
        )


class TestValidateColumns(unittest.TestCase):
    """Return True iff all required columns are present in the header."""

    def test_all_columns_present_returns_true(self) -> None:
        all_cols = [
            "incident_id",
            "file_name",
            "data_owner",
            "ssn",
            "policy_action",
            "incident_notes",
        ]
        self.assertTrue(IncidentSanitizer._validate_columns(all_cols))

    def test_one_column_missing_returns_false(self) -> None:
        cols_without_ssn = [
            "incident_id",
            "file_name",
            "data_owner",
            "policy_action",
            "incident_notes",
        ]
        self.assertFalse(IncidentSanitizer._validate_columns(cols_without_ssn))

    def test_empty_header_returns_false(self) -> None:
        self.assertFalse(IncidentSanitizer._validate_columns([]))


class TestReplaceNoneWithEmpty(unittest.TestCase):
    """Replace None cell values with empty strings."""

    def test_none_becomes_empty_string(self) -> None:
        self.assertEqual(
            IncidentSanitizer._replace_none_with_empty({"a": None}),
            {"a": ""},
        )

    def test_non_none_value_is_unchanged(self) -> None:
        self.assertEqual(
            IncidentSanitizer._replace_none_with_empty({"a": "hello"}),
            {"a": "hello"},
        )

    def test_mixed_row_is_handled(self) -> None:
        row = {"a": "x", "b": None, "c": "y"}
        self.assertEqual(
            IncidentSanitizer._replace_none_with_empty(row),
            {"a": "x", "b": "", "c": "y"},
        )


if __name__ == "__main__":
    unittest.main()
