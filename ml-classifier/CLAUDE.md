# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Environment Setup

```bash
# Create virtualenv and install dependencies (uses highest available Python 3.x)
./setup.sh

# Activate the virtualenv for subsequent commands
source .venv/bin/activate
```

The virtual environment is Python 3.9 (`.venv/`). Dependencies are in `requirements.txt`: `dataclasses`, `pandas`, `pkgconfig`, `setuptools`, `wheel`, `scikit-learn`, `joblib`, `numpy`, `matplotlib`, `seaborn`, `pytest`.

## Running the SBOM Extractor (standalone CLI)

The extractor CLI lives inside the classifier package. The old path (`src/sbom_extractor.py`) is a backward-compatibility shim that forwards to it.

```bash
# Process a single SBOM file, output JSON to stdout
python src/classifier/sbom_extractor.py -s <path/to/sbom.json>

# Process an entire directory of SBOM files, output CSV
python src/classifier/sbom_extractor.py -s <path/to/sbom-dir/> -f csv

# Write output to a file instead of stdout
python src/classifier/sbom_extractor.py -s <path/to/sbom.json> -f csv -o output.csv

# Append ALLOW/WARN/BLOCK rule-based classification column to the output
python src/classifier/sbom_extractor.py -s <path/to/sbom-dir/> -f csv -c
```

## Running the ML Classifier CLI

```bash
# Train the Decision Tree on all three data buckets
python src/classifier/cli.py train \
    --manifests-dir data/image-lists/ \
    --data-root data/scans/ \
    --output-dir analysis/

# Predict from a single SBOM file (requires trained artifacts in analysis/)
python src/classifier/cli.py predict \
    --sbom data/scans/high-qual/alpine-3.18.json \
    --artifact-dir analysis/ \
    --format json

# Predict from a directory of SBOMs, write CSV to file
python src/classifier/cli.py predict \
    --sbom data/scans/high-qual/ \
    --artifact-dir analysis/ \
    --format csv \
    --output results.csv
```

## Running Tests

```bash
# Run the full test suite from the ml-classifier/ directory
python -m pytest tests/ -v
```

Tests live in `tests/` and cover `data_loader`, `trainer`, `predictor`, and `reporting`. `tests/conftest.py` adds `src/` to `sys.path` so both the `classifier` package and the `sbom_extractor` shim are importable without installation.

## Generating SBOM Scan Data

```bash
# Scan a single image (requires trivy and sudo)
./scripts/generate_sbom.sh GENERATE_SBOM <image:tag> <output.json>

# Scan all images listed in a CSV file
./scripts/generate_sbom.sh GENERATE_SBOM_FROM_LIST <image-list.csv> <output-dir/>

# Scan all three training buckets sequentially (default) or in parallel
./scripts/scan_all.sh <output-dir>
./scripts/scan_all.sh -p <output-dir>
```

Image lists are in `data/image-lists/` as CSV files with format `image:tag,output-filename.json`. Three classification buckets exist: `high-qual.csv`, `aged-stale.csv`, `known-vuln.csv`.

### Docker Hub Prerequisites and Rate-Limit Constraints

`scan_all.sh` (and `generate_sbom.sh`) pull images from Docker Hub via Trivy. **A Docker Hub account login is required before running any scan.**

```bash
docker login
```

**Rate limit:** A personal authenticated account is capped at **200 pulls per 6-hour window**. Exceeding this will cause Trivy pulls to fail mid-scan.

Scaling constraints to keep in mind:
- The three current image lists total fewer than 200 images and fit within one window when run sequentially or in parallel.
- Adding images to the lists risks hitting the cap, especially with `-p` / `--parallel` where all three buckets pull simultaneously.
- If the cap is hit, wait out the 6-hour window or switch to a Docker Hub account with a higher pull tier (Pro/Team) before re-running.

## Computing Dataset Statistics

```bash
# Print per-feature min/median/mean/max for all three training buckets
python analysis/compute_statistics.py
```

Full statistical analysis, feature rubric rationale, and threshold derivations are documented in `analysis/dataset-statistics.md`.

## Architecture

This is an ML classifier for container image supply chain risk assessment. The pipeline has four stages:

**Stage 1 — Training Data Generation** (`scripts/`)
- Uses [Trivy](https://github.com/aquasecurity/trivy) to scan Docker images and produce CycloneDX-format SBOM JSON files
- Pre-scanned results are stored in `data/scans/high-qual/`, `data/scans/aged-stale/`, and `data/scans/known-vuln/`, corresponding to the three training labels

**Stage 2 — Feature Extraction** (`src/classifier/sbom_extractor.py`)
- Parses CycloneDX JSON SBOMs and extracts a fixed-length `SecurityMetric` feature vector
- Features (9): `total_dependency_count`, `vuln_total`, `critical_cve_count`, `high_cve_count`, `cvss_ge_7_count`, `max_cvss`, `unique_cwe_count`, `top25_cwe_count`, `base_image_age_days`
- SAST/Semgrep features (`semgrep_total`, `semgrep_high_count`) were removed from current scope; rationale is in `research/ML_model/semgrep-feature-analysis.md`
- `base_image_age_days` uses a two-tier strategy: (1) label fallback chain in `.metadata.component.properties`; (2) Docker Hub public API via `aquasecurity:trivy:Reference` (5s timeout, falls back to `0.0`)
- Severity ratings use the highest rating across all sources per vulnerability (not NVD-only)
- Top 25 CWEs reference the MITRE 2025 list hardcoded in `TOP_25_CWES`
- `FEATURES` list is the single source of truth for feature ordering across training and prediction

**Stage 3 — Rule-Based Classification** (`src/classifier/sbom_extractor.py`)
- `BLOCK_THRESHOLDS` and `WARN_THRESHOLDS` define per-feature cutoffs; BLOCK is evaluated before WARN
- `classify_metric(metric: SecurityMetric) -> str` returns `"BLOCK"`, `"WARN"`, or `"ALLOW"`
- Used during dataset loading to populate the `rule_label` column that the Decision Tree trains against

**Stage 4 — ML Training and Prediction** (`src/classifier/`)
- `data_loader.py` — reads bucket manifests, calls the extractor for each SBOM, builds a labeled DataFrame
- `trainer.py` (`Trainer`) — fits a `DecisionTreeClassifier`, runs stratified K-fold CV, returns a `TrainingResult`
- `predictor.py` (`Predictor`) — loads saved pkl artifacts and exposes `predict(metric)` / `predict_from_dict(dict)`
- `results.py` (`TrainingConfig`, `TrainingResult`) — hyperparameter dataclass and training output bundle; also contains all visualization and reporting functions
- `cli.py` — `train` and `predict` subcommands; run directly with `python src/classifier/cli.py`

## Package Layout

```
src/
  sbom_extractor.py          # Backward-compat shim — re-exports from classifier/sbom_extractor.py
  classifier/
    __init__.py              # Public API: Trainer, Predictor, TrainingConfig, TrainingResult,
                             #             SecurityMetric, FEATURES, classify_metric,
                             #             build_security_metric_from_sbom
    sbom_extractor.py        # Feature extraction, SecurityMetric dataclass, rule-based classifier
    data_loader.py           # Dataset loading from bucket manifests
    trainer.py               # DecisionTreeClassifier training pipeline
    predictor.py             # ML inference from saved artifacts
    results.py               # TrainingConfig, TrainingResult, visualization and reporting functions
    cli.py                   # Train and predict CLI entry point
tests/
  conftest.py                # Adds src/ to sys.path for both package and shim imports
  test_data_loader.py
  test_trainer.py
  test_predictor.py
  test_reporting.py
```

## Key Import Note

`cli.py` is designed to run both as a direct script and as part of the package. It adds `src/` to `sys.path` at startup and uses absolute imports (`from classifier import ...`) rather than relative ones, so `python src/classifier/cli.py` works without installation.

The shim at `src/sbom_extractor.py` exists solely for backward compatibility with the old CLI path and with any code that does `import sbom_extractor`. New code should import directly from the `classifier` package.
