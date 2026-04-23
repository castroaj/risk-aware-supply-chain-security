# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Risk-Aware Compliance-as-Code: An ML-Gated Secure CI/CD Pipeline for Software Supply Chain Integrity**

The goal is a GitHub Actions CI/CD pipeline that runs SBOM generation, vulnerability scanning (Trivy), and SAST (Semgrep) on container images, feeds the results into an ML classifier (Decision Tree), and produces an ALLOW / WARN / BLOCK deployment decision with a full audit trail.

## Repository Structure

```
ml-classifier/                      # ML pipeline — feature extraction, classification, training
  src/classifier/sbom_extractor.py  # Core feature extraction + rule-based classification CLI
  scripts/                          # Trivy scan scripts
  data/                             # Image lists (CSV), pre-scanned SBOM JSON files, label CSVs
  analysis/                         # Dataset analysis docs and training run comparisons
  pyproject.toml / Makefile / setup.sh / CLAUDE.md
software-prototype/                 # CI/CD pipeline prototype — GitHub Actions workflow, Docker, uv
  app/                              # Python package (main entry point)
  Dockerfile / Makefile / pyproject.toml / uv.lock
research/               # Design research docs (SBOM, SAST, dynamic scanning, ML model)
documentation/          # SRS, design diagrams, meeting notes
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

# Label — extract features and assign rule labels; write per-bucket CSVs to data/labels/
risk-classifier-label \
    --manifests-dir data/image-lists/ \
    --data-root data/scans/

# Train the Decision Tree from pre-labeled CSVs
risk-classifier-train \
    --labels-dir data/labels/ \
    --output-dir training-runs/

# Classify a single SBOM (CI/CD pipeline workflow)
risk-classifier-predict \
    --sbom data/scans/high-qual/alpine-3.18.json \
    --artifact-dir analysis/ \
    --format json
```

> **Docker Hub prerequisite:** All scan scripts pull images via Trivy and require `docker login` before running. Personal authenticated accounts are capped at **200 pulls per 6-hour window** — a hard constraint when scaling up image lists or using `-p` / `--parallel`.

## Active Code: `software-prototype/`

A CI/CD pipeline prototype with a GitHub Actions workflow (`.github/workflows/software-prototype-build.yml`) that triggers on changes to `software-prototype/`. The workflow:

1. Builds and smoke-tests the Python app (`uv run software-prototype`)
2. Builds package artifacts and a Docker image
3. Runs Trivy to generate a CycloneDX SBOM and vulnerability report
4. Enforces policy by failing CI on any `CRITICAL` vulnerability
5. Uploads `dist/*` and scan reports as CI artifacts

```bash
cd software-prototype

# Install dependencies
make install    # runs: uv sync

# Run the application
make run        # runs: uv run software-prototype

# Build and run Docker image
make docker-build
make docker-run
```

## ML Pipeline Architecture

The classifier operates on **structured feature vectors** extracted from tool outputs — it never processes raw source code or binary artifacts directly.

**Three training label buckets** (each has a pre-scanned JSON directory and an image-list CSV):
| Label bucket | Directory | Image list CSV | Label CSV |
|---|---|---|---|
| `ALLOW` candidates | `data/scans/high-qual/` | `data/image-lists/high-qual.csv` | `data/labels/high-qual-labels.csv` |
| `WARN`/`BLOCK` candidates | `data/scans/aged-stale/` | `data/image-lists/aged-stale.csv` | `data/labels/aged-stale-labels.csv` |
| `BLOCK` candidates | `data/scans/known-vuln/` | `data/image-lists/known-vuln.csv` | `data/labels/known-vuln-labels.csv` |

**Feature vector** (8 features, all from CycloneDX JSON produced by Trivy):
- `total_dependency_count`, `vuln_total`, `critical_cve_count`, `high_cve_count`, `cvss_ge_7_count`, `max_cvss`, `unique_cwe_count`, `top25_cwe_count`
- SAST features (`semgrep_total`, `semgrep_high_count`) are deferred from the current scope; see `research/ML_model/semgrep-feature-analysis.md` for rationale

**Classification** is rule-based (`BLOCK_THRESHOLDS` / `WARN_THRESHOLDS` in `src/classifier/sbom_extractor.py`) for labeling, and Decision Tree (`DecisionTreeClassifier`) for ML training. Labels are frozen at scan time in `data/labels/` CSVs so threshold changes or Docker Hub API non-determinism produce a visible `git diff` rather than a silent accuracy drop. Threshold rationale is in `ml-classifier/analysis/dataset-statistics.md`.

## Key Design Decisions

- Severity ratings use the **highest rating across all sources** per vulnerability (not NVD-only).
- Top 25 CWEs reference the **MITRE 2025** list hardcoded in `TOP_25_CWES`.
- SBOM format is **CycloneDX JSON** produced by `trivy image --format cyclonedx`.
- The ML classifier is **not autonomous** — final deployment authority belongs to designated human reviewers with an override + retraining feedback loop.

## Research Documentation

Key design documents under `research/ML_model/`:
- `classification-proposal.md` — full ML methodology, model selection rationale (Decision Tree), evaluation metrics
- `feature-extraction.md` — per-feature WHAT/WHY/WHERE rationale
- `training-data-generation-plan.md` — labeling rubric, data sourcing strategy
