# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Risk-Aware Compliance-as-Code: An ML-Gated Secure CI/CD Pipeline for Software Supply Chain Integrity**

The goal is a GitHub Actions CI/CD pipeline that runs SBOM generation, vulnerability scanning (Trivy), and SAST (Semgrep) on container images, feeds the results into an ML classifier (Decision Tree), and produces an ALLOW / WARN / BLOCK deployment decision with a full audit trail.

## Repository Structure

```
ml-classifier/                      # Only active code — feature extraction, classification, training data
  src/classifier/sbom_extractor.py  # Core feature extraction + rule-based classification CLI
  scripts/                          # Trivy scan scripts
  data/                             # Image lists (CSV) and pre-scanned SBOM JSON files
  analysis/                         # Statistics script and dataset analysis docs
  pyproject.toml / Makefile / setup.sh / CLAUDE.md
research/               # Design research docs (SBOM, SAST, dynamic scanning, ML model)
documentation/          # SRS, design diagrams, meeting notes
software-prototype/     # Placeholder (not yet implemented)
```

## Active Code: `ml-classifier/`

See `ml-classifier/CLAUDE.md` for full commands. Quick reference:

```bash
cd ml-classifier

# Environment setup (Makefile shorthand or direct)
make install && source .venv/bin/activate
# equivalent: ./setup.sh && source .venv/bin/activate

# Run feature extractor on a single SBOM file
python src/classifier/sbom_extractor.py -s <path/to/sbom.json>

# Extract + classify an entire directory, output CSV
python src/classifier/sbom_extractor.py -s data/scans/high-qual/ -f csv -c

# Scan a Docker image (requires trivy + sudo)
./scripts/generate_sbom.sh GENERATE_SBOM <image:tag> <output.json>

# Scan all images in a list CSV
./scripts/generate_sbom.sh GENERATE_SBOM_FROM_LIST \
    data/image-lists/high-qual.csv \
    data/scans/high-qual/

# Scan all three training buckets (sequential default, or parallel with -p)
./scripts/scan_all.sh data/scans/
./scripts/scan_all.sh -p data/scans/

# Print dataset statistics across all three training buckets
python analysis/compute_statistics.py
```

> **Docker Hub prerequisite:** All scan scripts pull images via Trivy and require `docker login` before running. Personal authenticated accounts are capped at **200 pulls per 6-hour window** — a hard constraint when scaling up image lists or using `-p` / `--parallel`.

## ML Pipeline Architecture

The classifier operates on **structured feature vectors** extracted from tool outputs — it never processes raw source code or binary artifacts directly.

**Three training label buckets** (each has a pre-scanned JSON directory and an image-list CSV):
| Label bucket | Directory | Image list CSV |
|---|---|---|
| `ALLOW` candidates | `data/scans/high-qual/` | `data/image-lists/high-qual.csv` |
| `WARN`/`BLOCK` candidates | `data/scans/aged-stale/` | `data/image-lists/aged-stale.csv` |
| `BLOCK` candidates | `data/scans/known-vuln/` | `data/image-lists/known-vuln.csv` |

**Feature vector** (9 features, all from CycloneDX JSON produced by Trivy):
- `total_dependency_count`, `vuln_total`, `critical_cve_count`, `high_cve_count`, `cvss_ge_7_count`, `max_cvss`, `unique_cwe_count`, `top25_cwe_count`
- `base_image_age_days` — two-tier: label fallback chain → Docker Hub public API
- SAST features (`semgrep_total`, `semgrep_high_count`) are deferred from the current scope; see `research/ML_model/semgrep-feature-analysis.md` for rationale

**Classification** is currently rule-based (`BLOCK_THRESHOLDS` / `WARN_THRESHOLDS` constants in `src/classifier/sbom_extractor.py`). The Decision Tree model training step has not been implemented yet. Threshold rationale is in `ml-classifier/analysis/dataset-statistics.md`.

## Key Design Decisions

- Severity ratings use the **highest rating across all sources** per vulnerability (not NVD-only).
- Top 25 CWEs reference the **MITRE 2025** list hardcoded in `TOP_25_CWES`.
- SBOM format is **CycloneDX JSON** produced by `trivy image --format cyclonedx`.
- `base_image_age_days` returns `0.0` when no timestamp label is found and the Docker Hub API call fails or times out (5s). Images where the tag was republished after scanning also return `0.0`.
- The ML classifier is **not autonomous** — final deployment authority belongs to designated human reviewers with an override + retraining feedback loop.

## Research Documentation

Key design documents under `research/ML_model/`:
- `classification-proposal.md` — full ML methodology, model selection rationale (Decision Tree), evaluation metrics
- `feature-extraction.md` — per-feature WHAT/WHY/WHERE rationale
- `training-data-generation-plan.md` — labeling rubric, data sourcing strategy
