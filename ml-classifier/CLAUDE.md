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
python sbom_extractor.py -s <path/to/sbom.json>

# Process an entire directory of SBOM files, output CSV
python sbom_extractor.py -s <path/to/sbom-dir/> -f csv

# Write output to a file instead of stdout
python sbom_extractor.py -s <path/to/sbom.json> -f csv -o output.csv
```

## Generating SBOM Scan Data

```bash
# Scan a single image (requires trivy and sudo)
./training-set-generation/generate_sbom.sh GENERATE_SBOM <image:tag> <output.json>

# Scan all images listed in a CSV file
./training-set-generation/generate_sbom.sh GENERATE_SBOM_FROM_LIST <image-list.csv> <output-dir/>
```

Image lists are in `training-set-generation/image-lists/` as CSV files with format `image:tag,output-filename.json`. Three classification buckets exist: `high-qual.csv`, `aged-stale.csv`, `known-vuln.csv`.

## Architecture

This is an ML classifier for container image supply chain risk assessment. The pipeline has two stages:

**Stage 1 — Training Data Generation** (`training-set-generation/`)
- Uses [Trivy](https://github.com/aquasecurity/trivy) to scan Docker images and produce CycloneDX-format SBOM JSON files
- Pre-scanned results are stored in `high-qual-vuln-scan/`, `aged-stale-vuln-scan/`, and `list-vuln-scan/` subdirectories, corresponding to the three training labels

**Stage 2 — Feature Extraction** (`sbom_extractor.py`)
- Parses CycloneDX JSON SBOMs and extracts a fixed-length `SecurityMetric` feature vector
- Features: `total_dependency_count`, `vuln_total`, `critical_cve_count`, `high_cve_count`, `cvss_ge_7_count`, `max_cvss`, `unique_cwe_count`, `top25_cwe_count`, `semgrep_total`, `semgrep_high_count`, `base_image_age_days`
- `semgrep_total` and `semgrep_high_count` are currently passed in externally (defaulting to 0 in the CLI); SAST integration is not yet implemented
- `base_image_age_days` uses a two-tier extraction strategy: (1) a label fallback chain checks `aquasecurity:trivy:Labels:build-date`, `org.opencontainers.image.created`, `org.label-schema.build-date`, and `com.docker.dhi.created` in `.metadata.component.properties`; (2) if no label resolves, the Docker Hub public API is queried using `aquasecurity:trivy:Reference` (5-second timeout, gracefully falls back to `0.0` on failure). Images where the tag was republished after the scan was taken will still return `0.0`.
- The `SecurityMetricsCollection` wraps multiple `SecurityMetric` objects into a pandas DataFrame and exports to CSV or JSON
- Severity ratings use the highest rating across all sources per vulnerability (not NVD-only)
- Top 25 CWEs reference the MITRE 2025 list hardcoded in `TOP_25_CWES`