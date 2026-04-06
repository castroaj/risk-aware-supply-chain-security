"""
data_loader.py
==============
Load SBOM scan data from bucket manifests and build a labeled pandas DataFrame
ready for Trainer.

All functions are pure given the filesystem state: no model loading, no training,
no visualization. Missing or unparsable files produce warnings to stderr and are
skipped rather than raising, so a partial dataset is always preferred over a crash.

Bucket layout expected by load_dataset():
    manifests_dir/
        high-qual.csv       → ALLOW bucket
        aged-stale.csv      → WARN bucket
        known-vuln.csv      → BLOCK bucket

    data_root/
        high-qual/          → SBOM JSON files for the ALLOW bucket
        aged-stale/         → SBOM JSON files for the WARN bucket
        known-vuln/         → SBOM JSON files for the BLOCK bucket

CSV format (one row per image):
    image:tag,output-filename.json
"""

from pathlib import Path
from typing import Dict, List, Optional
from .sbom_extractor import build_security_metric_from_sbom, classify_metric, SecurityMetric, FEATURES

import csv
import json
import sys
import pandas as pd

# Canonical mapping from bucket directory name to its bucket-level label.
# These labels reflect the intent of the data sourcing strategy, not the
# per-image rule-based classification (which is stored in the rule_label column).
BUCKET_LABEL_MAP: Dict[str, str] = {
    "high-qual":  "ALLOW",
    "aged-stale": "WARN",
    "known-vuln": "BLOCK",
}

# Ordered list of manifest CSV filenames, one per bucket.
_MANIFEST_FILES: Dict[str, str] = {
    "high-qual":  "high-qual.csv",
    "aged-stale": "aged-stale.csv",
    "known-vuln": "known-vuln.csv",
}

# DataFrame columns that must be present for Trainer to consume the output.
REQUIRED_COLUMNS: List[str] = (
    ["scan_file", "image", "bucket", "bucket_label", "rule_label"]
    + FEATURES
)


def find_sbom_json(
    json_filename: str, bucket_name: str, data_root: Path
) -> Optional[Path]:
    """
    Search for a named SBOM JSON file across a prioritized set of candidate paths.

    WHAT:
        Checks candidate paths in order: bucket subdirectory first, then the flat
        data_root, then falls back to a recursive glob across all of data_root.

    WHY:
        Scan files may live in bucket-named subdirectories (canonical layout) or in
        a flat directory depending on how scan_all.sh was invoked. The search order
        prefers the canonical layout and degrades gracefully.

    WHERE:
        Reads only the filesystem; produces no side effects.
        Returns None (not a raised exception) when the file cannot be located, so
        the caller can log a warning and skip rather than abort the dataset load.

    Args:
        json_filename: Bare filename as it appears in the CSV manifest
                       (e.g. "alpine-3.18.json").
        bucket_name:   One of the canonical bucket names
                       ("high-qual", "aged-stale", "known-vuln").
        data_root:     Root directory under which scan bucket directories are expected.

    Returns:
        Resolved Path if a matching file is found, None otherwise.
    """
    candidates = [
        data_root / bucket_name / json_filename,
        data_root / json_filename,
    ]
    for path in candidates:
        if path.exists():
            return path.resolve()

    matches = list(data_root.rglob(json_filename))
    return matches[0].resolve() if matches else None


def load_bucket(
    manifest_csv: Path, bucket_name: str, data_root: Path
) -> pd.DataFrame:
    """
    Read one image-list CSV manifest and build a labeled DataFrame for that bucket.

    WHAT:
        For each row in the manifest CSV, locates the SBOM JSON file, calls
        sbom_extractor.build_security_metric_from_sbom() to extract the 9 features,
        calls sbom_extractor.classify_metric() to obtain the rule-based label, and
        accumulates results into a DataFrame.

    WHY:
        Encapsulates the single-bucket loading loop so it can be called independently
        (for partial loads or testing) and so that Trainer receives a ready DataFrame
        rather than raw paths. Delegates all SBOM parsing to sbom_extractor to avoid
        reimplementing extraction logic.

    WHERE:
        Reads the manifest CSV and SBOM JSON files from the filesystem.
        Logs warnings to stderr for missing files or parse failures; does not raise.
        Returns an empty DataFrame (with correct columns) if no records could be loaded.

    Args:
        manifest_csv: Path to one CSV file with rows of the form
                      "image:tag,filename.json".
        bucket_name:  Key into BUCKET_LABEL_MAP for the bucket-level label.
        data_root:    Root directory containing SBOM JSON files.

    Returns:
        pd.DataFrame with columns: scan_file, image, bucket, bucket_label,
        rule_label, total_dependency_count, vuln_total, critical_cve_count,
        high_cve_count, cvss_ge_7_count, max_cvss, unique_cwe_count,
        top25_cwe_count, base_image_age_days.
    """
    bucket_label = BUCKET_LABEL_MAP[bucket_name]
    records: List[dict] = []

    if not manifest_csv.exists():
        print(
            f"[WARN] manifest not found: {manifest_csv} — skipping bucket '{bucket_name}'",
            file=sys.stderr,
        )
        return _empty_dataframe()

    with open(manifest_csv, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or len(row) < 2:
                continue
            image_tag = row[0].strip()
            json_filename = row[1].strip()

            json_path = find_sbom_json(json_filename, bucket_name, data_root)
            if json_path is None:
                print(
                    f"[WARN] SBOM JSON not found for {image_tag} ({json_filename}) — skipping",
                    file=sys.stderr,
                )
                continue

            try:
                with open(json_path, encoding="utf-8") as jf:
                    sbom = json.load(jf)
            except (json.JSONDecodeError, OSError) as exc:
                print(
                    f"[WARN] could not parse {json_path}: {exc} — skipping",
                    file=sys.stderr,
                )
                continue

            try:
                metric = build_security_metric_from_sbom(str(json_path), sbom)
            except Exception as exc:
                print(
                    f"[WARN] feature extraction failed for {json_path}: {exc} — skipping",
                    file=sys.stderr,
                )
                continue

            rule_label = classify_metric(metric)

            records.append(
                {
                    "scan_file":    str(json_path),
                    "image":        image_tag,
                    "bucket":       bucket_name,
                    "bucket_label": bucket_label,
                    "rule_label":   rule_label,
                    **{f: getattr(metric, f) for f in FEATURES},
                }
            )

    return pd.DataFrame(records, columns=REQUIRED_COLUMNS) if records else _empty_dataframe()


def load_dataset(manifests_dir: Path, data_root: Path) -> pd.DataFrame:
    """
    Load and concatenate all three training buckets into a single DataFrame.

    WHAT:
        Calls load_bucket() for each of the three canonical bucket names and
        concatenates the results. Raises RuntimeError if the combined DataFrame
        is empty (no records loaded at all).

    WHY:
        Provides a single entry point that Trainer can call. The three-bucket
        structure is an invariant of the current dataset design; expressing it
        here avoids spreading bucket names into Trainer.

    WHERE:
        Expects manifests_dir to contain high-qual.csv, aged-stale.csv, and
        known-vuln.csv. Missing individual manifests are warned and skipped;
        all three missing raises RuntimeError.

    Args:
        manifests_dir: Directory containing the three manifest CSV files.
        data_root:     Root directory under which scan bucket directories live.

    Returns:
        Concatenated pd.DataFrame of all successfully loaded records.

    Raises:
        RuntimeError: If no records were loaded across all three buckets.
    """
    frames: List[pd.DataFrame] = []

    for bucket_name, csv_file in _MANIFEST_FILES.items():
        frame = load_bucket(manifests_dir / csv_file, bucket_name, data_root)
        if not frame.empty:
            frames.append(frame)

    if not frames:
        raise RuntimeError(
            f"No records loaded. Check that manifests exist in '{manifests_dir}' "
            f"and SBOM JSONs are under '{data_root}'."
        )

    combined = pd.concat(frames, ignore_index=True)

    if combined.empty:
        raise RuntimeError(
            f"No records loaded. All manifests were empty or all SBOM files were missing."
        )

    return combined


def metric_from_row(row: pd.Series) -> SecurityMetric:
    """
    Reconstruct a SecurityMetric dataclass from a DataFrame row.

    WHAT:
        Maps the 9 feature columns (plus scan_file) from a pandas Series back into
        the SecurityMetric dataclass used by Predictor.predict().

    WHY:
        Predictor.predict() accepts a SecurityMetric; this helper lets callers
        convert a DataFrame row (e.g., from a loaded dataset) into the canonical
        input type without importing SecurityMetric directly.

    WHERE:
        Pure function; no I/O. Expects the row to contain a 'scan_file' column
        and all columns listed in sbom_extractor.FEATURES.

    Args:
        row: A pandas Series containing 'scan_file' and all 9 feature columns.

    Returns:
        SecurityMetric with all fields populated from the row.
    """
    return SecurityMetric(
        scan_file=str(row.get("scan_file", "")),
        **{f: float(row[f]) for f in FEATURES},
    )


def _empty_dataframe() -> pd.DataFrame:
    """Return an empty DataFrame with the canonical column schema."""
    return pd.DataFrame(columns=REQUIRED_COLUMNS)
