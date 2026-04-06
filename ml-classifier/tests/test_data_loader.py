"""
test_data_loader.py
===================
Unit tests for classifier.data_loader.

Tests cover:
    - find_sbom_json path resolution priority
    - load_bucket warning-and-skip behavior
    - load_bucket DataFrame column contract
    - load_bucket rule_label consistency with classify_metric
    - load_dataset RuntimeError on empty input
    - metric_from_row field mapping
"""

import csv
import json
from pathlib import Path

import pandas as pd
import pytest

import sbom_extractor as _extractor
from classifier.data_loader import (
    REQUIRED_COLUMNS,
    find_sbom_json,
    load_bucket,
    load_dataset,
    metric_from_row,
)


# ---------------------------------------------------------------------------
# Minimal valid CycloneDX SBOM fixture (no vulnerabilities, no components)
# ---------------------------------------------------------------------------

def _minimal_sbom(timestamp: str = "2025-01-01T00:00:00Z") -> dict:
    return {
        "metadata": {"timestamp": timestamp, "component": {"properties": []}},
        "components": [],
        "vulnerabilities": [],
    }


def _write_sbom(path: Path, sbom: dict = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sbom or _minimal_sbom()), encoding="utf-8")
    return path


def _write_manifest(path: Path, rows: list) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerows(rows)
    return path


# ---------------------------------------------------------------------------
# find_sbom_json
# ---------------------------------------------------------------------------

class TestFindSbomJson:
    def test_canonical_path_found_first(self, tmp_path):
        """Canonical bucket subdirectory takes priority over rglob."""
        bucket = "high-qual"
        filename = "test.json"

        # canonical path
        canonical = tmp_path / bucket / filename
        _write_sbom(canonical)

        # rglob-only path (should NOT be returned)
        other = tmp_path / "other" / filename
        _write_sbom(other)

        result = find_sbom_json(filename, bucket, tmp_path)
        assert result == canonical.resolve()

    def test_flat_fallback_when_no_bucket_subdir(self, tmp_path):
        """Falls back to flat data_root when no bucket subdirectory exists."""
        filename = "flat.json"
        flat = tmp_path / filename
        _write_sbom(flat)

        result = find_sbom_json(filename, "high-qual", tmp_path)
        assert result == flat.resolve()

    def test_rglob_fallback(self, tmp_path):
        """Falls back to recursive glob when neither canonical nor flat path exists."""
        filename = "deep.json"
        nested = tmp_path / "a" / "b" / "c" / filename
        _write_sbom(nested)

        result = find_sbom_json(filename, "high-qual", tmp_path)
        assert result == nested.resolve()

    def test_returns_none_when_missing(self, tmp_path):
        """Returns None (not raises) when the file cannot be found anywhere."""
        result = find_sbom_json("nonexistent.json", "high-qual", tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# load_bucket
# ---------------------------------------------------------------------------

class TestLoadBucket:
    def _setup_bucket(self, tmp_path, n_images=3, bucket_name="high-qual"):
        """Create n_images SBOM JSONs and a manifest CSV for the given bucket."""
        data_root = tmp_path / "scans"
        manifests_dir = tmp_path / "manifests"

        manifest_rows = []
        for i in range(n_images):
            fname = f"image-{i}.json"
            _write_sbom(data_root / bucket_name / fname)
            manifest_rows.append([f"alpine:{i}", fname])

        manifest_path = _write_manifest(manifests_dir / f"{bucket_name}.csv", manifest_rows)
        return manifest_path, data_root

    def test_returns_correct_columns(self, tmp_path):
        """Returned DataFrame contains all REQUIRED_COLUMNS."""
        manifest_path, data_root = self._setup_bucket(tmp_path)
        df = load_bucket(manifest_path, "high-qual", data_root)
        assert not df.empty
        for col in REQUIRED_COLUMNS:
            assert col in df.columns, f"Missing column: {col}"

    def test_skips_missing_sbom_without_raising(self, tmp_path, capsys):
        """Rows referencing missing SBOM files are warned and skipped."""
        data_root = tmp_path / "scans"
        manifests_dir = tmp_path / "manifests"

        # One valid SBOM, one missing
        _write_sbom(data_root / "high-qual" / "present.json")
        manifest_path = _write_manifest(
            manifests_dir / "high-qual.csv",
            [["img:1", "present.json"], ["img:2", "missing.json"]],
        )

        df = load_bucket(manifest_path, "high-qual", data_root)
        assert len(df) == 1
        captured = capsys.readouterr()
        assert "missing.json" in captured.err

    def test_rule_label_matches_classify_metric(self, tmp_path):
        """rule_label column values match classify_metric() output for each row."""
        manifest_path, data_root = self._setup_bucket(tmp_path, n_images=2)
        df = load_bucket(manifest_path, "high-qual", data_root)
        assert not df.empty

        for _, row in df.iterrows():
            metric = metric_from_row(row)
            expected = _extractor.classify_metric(metric)
            assert row["rule_label"] == expected

    def test_missing_manifest_returns_empty(self, tmp_path, capsys):
        """Missing manifest CSV returns an empty DataFrame without raising."""
        df = load_bucket(tmp_path / "nonexistent.csv", "high-qual", tmp_path)
        assert df.empty
        assert "nonexistent.csv" in capsys.readouterr().err

    def test_row_count_matches_valid_sboms(self, tmp_path):
        """Number of rows in the DataFrame equals the number of valid SBOM files."""
        manifest_path, data_root = self._setup_bucket(tmp_path, n_images=5)
        df = load_bucket(manifest_path, "high-qual", data_root)
        assert len(df) == 5


# ---------------------------------------------------------------------------
# load_dataset
# ---------------------------------------------------------------------------

class TestLoadDataset:
    def _setup_all_buckets(self, tmp_path, counts=(3, 3, 3)):
        """Create three buckets with the given image counts."""
        data_root = tmp_path / "scans"
        manifests_dir = tmp_path / "manifests"
        buckets = [("high-qual", counts[0]), ("aged-stale", counts[1]), ("known-vuln", counts[2])]

        for bucket_name, n in buckets:
            rows = []
            for i in range(n):
                fname = f"{bucket_name}-{i}.json"
                _write_sbom(data_root / bucket_name / fname)
                rows.append([f"img:{i}", fname])
            _write_manifest(manifests_dir / f"{bucket_name}.csv", rows)

        return manifests_dir, data_root

    def test_raises_on_empty_result(self, tmp_path):
        """RuntimeError is raised when no records can be loaded."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(RuntimeError, match="No records loaded"):
            load_dataset(empty_dir, tmp_path)

    def test_concatenates_all_buckets(self, tmp_path):
        """Total row count equals sum across all three buckets."""
        manifests_dir, data_root = self._setup_all_buckets(tmp_path, counts=(3, 2, 1))
        df = load_dataset(manifests_dir, data_root)
        assert len(df) == 6
        assert set(df["bucket"].unique()) == {"high-qual", "aged-stale", "known-vuln"}


# ---------------------------------------------------------------------------
# metric_from_row
# ---------------------------------------------------------------------------

class TestMetricFromRow:
    def test_field_mapping(self, tmp_path):
        """metric_from_row correctly maps all 9 feature columns to SecurityMetric fields."""
        manifest_path, data_root = TestLoadBucket()._setup_bucket(tmp_path, n_images=1)
        df = load_bucket(manifest_path, "high-qual", data_root)
        assert not df.empty

        row = df.iloc[0]
        metric = metric_from_row(row)

        assert isinstance(metric, _extractor.SecurityMetric)
        for feat in _extractor.FEATURES:
            assert getattr(metric, feat) == float(row[feat])

    def test_scan_file_set(self, tmp_path):
        """metric_from_row populates scan_file from the row."""
        manifest_path, data_root = TestLoadBucket()._setup_bucket(tmp_path, n_images=1)
        df = load_bucket(manifest_path, "high-qual", data_root)
        metric = metric_from_row(df.iloc[0])
        assert metric.scan_file != ""
