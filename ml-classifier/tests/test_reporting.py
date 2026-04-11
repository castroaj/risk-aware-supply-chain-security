"""
test_reporting.py
=================
Unit tests for classifier.reporting.

Tests cover:
    - write_classification_report creates the output file
    - Report contains all required section headings
    - Accuracy value in the report matches result.test_accuracy
"""

import numpy as np
import pandas as pd
import pytest

from classifier.results import write_classification_report
from classifier.trainer import Trainer
from classifier import sbom_extractor as _extractor


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

def _synthetic_df(n_per_class: int = 10) -> pd.DataFrame:
    rng = np.random.default_rng(seed=2)
    rows = []
    for label, low, high in [("ALLOW", 0, 5), ("WARN", 15, 40), ("BLOCK", 55, 100)]:
        for _ in range(n_per_class):
            row = {f: rng.uniform(0, 5) for f in _extractor.FEATURES}
            row["critical_cve_count"] = rng.uniform(low, high)
            row["rule_label"] = label
            rows.append(row)
    df = pd.DataFrame(rows)
    df["scan_file"] = "fixture"
    return df


@pytest.fixture(scope="module")
def training_result():
    """Train once and reuse across all test functions in this module."""
    return Trainer(_synthetic_df()).train()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestWriteClassificationReport:
    def test_creates_file(self, training_result, tmp_path):
        """write_classification_report creates classification_report.txt."""
        path = write_classification_report(training_result, tmp_path)
        assert path.exists()
        assert path.name == "classification_report.txt"

    def test_returns_path(self, training_result, tmp_path):
        """Return value is a Path pointing to the written file."""
        path = write_classification_report(training_result, tmp_path)
        assert path.is_file()

    def test_contains_required_sections(self, training_result, tmp_path):
        """Report file contains all four required section headings."""
        path = write_classification_report(training_result, tmp_path)
        content = path.read_text(encoding="utf-8")

        for heading in [
            "Test Accuracy",
            "CV Accuracy",
            "Classification Report",
            "Decision Tree Rules",
        ]:
            assert heading in content, f"Missing required section: '{heading}'"

    def test_accuracy_value_matches_result(self, training_result, tmp_path):
        """The Test Accuracy value written to the report matches result.test_accuracy."""
        path = write_classification_report(training_result, tmp_path)
        content = path.read_text(encoding="utf-8")

        expected = f"{training_result.test_accuracy:.4f}"
        assert expected in content, (
            f"Expected accuracy '{expected}' not found in report. "
            f"Excerpt: {content[:500]}"
        )

    def test_creates_output_dir_if_missing(self, training_result, tmp_path):
        """write_classification_report creates the output directory if absent."""
        new_dir = tmp_path / "reports"
        assert not new_dir.exists()
        write_classification_report(training_result, new_dir)
        assert new_dir.exists()
