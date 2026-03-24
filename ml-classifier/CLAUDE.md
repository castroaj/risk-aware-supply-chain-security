# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Environment Setup

```bash
# Create virtualenv and install dependencies (uses highest available Python 3.x)
./setup.sh

# Activate the virtualenv for subsequent commands
source .venv/bin/activate
```

The virtual environment is Python 3.9 (`.venv/`). Dependencies are in `requirements.txt`: `dataclasses`, `pandas`, `pkgconfig`, `setuptools`, `wheel`.

## Running the SBOM Extractor

```bash
# Process a single SBOM file, output JSON to stdout
python src/sbom_extractor.py -s <path/to/sbom.json>

# Process an entire directory of SBOM files, output CSV
python src/sbom_extractor.py -s <path/to/sbom-dir/> -f csv

# Write output to a file instead of stdout
python src/sbom_extractor.py -s <path/to/sbom.json> -f csv -o output.csv

# Append ALLOW/WARN/BLOCK classification column to the output
python src/sbom_extractor.py -s <path/to/sbom-dir/> -f csv -c
```

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

This is an ML classifier for container image supply chain risk assessment. The pipeline has three stages:

**Stage 1 — Training Data Generation** (`scripts/`)
- Uses [Trivy](https://github.com/aquasecurity/trivy) to scan Docker images and produce CycloneDX-format SBOM JSON files
- Pre-scanned results are stored in `data/scans/high-qual/`, `data/scans/aged-stale/`, and `data/scans/known-vuln/`, corresponding to the three training labels

**Stage 2 — Feature Extraction** (`src/sbom_extractor.py`)
- Parses CycloneDX JSON SBOMs and extracts a fixed-length `SecurityMetric` feature vector
- Features (9): `total_dependency_count`, `vuln_total`, `critical_cve_count`, `high_cve_count`, `cvss_ge_7_count`, `max_cvss`, `unique_cwe_count`, `top25_cwe_count`, `base_image_age_days`
- SAST/Semgrep features (`semgrep_total`, `semgrep_high_count`) were removed from the current implementation scope; rationale is in `research/ML_model/semgrep-feature-analysis.md`
- `base_image_age_days` uses a two-tier extraction strategy: (1) a label fallback chain checks `aquasecurity:trivy:Labels:build-date`, `org.opencontainers.image.created`, `org.label-schema.build-date`, and `com.docker.dhi.created` in `.metadata.component.properties`; (2) if no label resolves, the Docker Hub public API is queried using `aquasecurity:trivy:Reference` (5-second timeout, gracefully falls back to `0.0` on failure). Images where the tag was republished after the scan was taken will still return `0.0`.
- The `SecurityMetricsCollection` wraps multiple `SecurityMetric` objects into a pandas DataFrame and exports to CSV or JSON
- Severity ratings use the highest rating across all sources per vulnerability (not NVD-only)
- Top 25 CWEs reference the MITRE 2025 list hardcoded in `TOP_25_CWES`

**Stage 3 — Rule-Based Classification** (`src/sbom_extractor.py`)
- `BLOCK_THRESHOLDS` and `WARN_THRESHOLDS` module-level constants define per-feature cutoffs; BLOCK is evaluated before WARN and any single breach returns that verdict
- `classify_metric(metric: SecurityMetric) -> str` is a public function that returns `"BLOCK"`, `"WARN"`, or `"ALLOW"`; can be called programmatically independent of the CLI
- `-c / --classify` CLI flag appends a `classification` column to the output; works with both CSV and JSON formats
- Threshold values and feature selection rationale are documented in `analysis/dataset-statistics.md`
