# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Risk-Aware Compliance-as-Code: An ML-Gated Secure CI/CD Pipeline for Software Supply Chain Integrity**

The goal is a GitHub Actions CI/CD pipeline that runs SBOM generation, vulnerability scanning (Trivy), and SAST (Semgrep) on container images, feeds the results into an ML classifier (Decision Tree), and produces an ALLOW / WARN / BLOCK deployment decision with a full audit trail.

## Repository Structure

```
ml-classifier/          # Only active code — feature extraction, classification, training data
  sbom_extractor.py     # Core feature extraction + rule-based classification CLI
  training-set-generation/   # Trivy scan scripts and image lists (CSV)
  training-set-classification/  # Pre-scanned SBOM JSON files and statistics script
  requirements.txt / setup.sh / CLAUDE.md
research/               # Design research docs (SBOM, SAST, dynamic scanning, ML model)
documentation/          # SRS, design diagrams, meeting notes
software-prototype/     # Placeholder (not yet implemented)
```

## Active Code: `ml-classifier/`

See `ml-classifier/CLAUDE.md` for full commands. Quick reference:

```bash
cd ml-classifier

# Environment setup
./setup.sh && source .venv/bin/activate

# Run feature extractor on a single SBOM file
python sbom_extractor.py -s <path/to/sbom.json>

# Extract + classify an entire directory, output CSV
python sbom_extractor.py -s training-set-classification/high-qual-vuln-scan/ -f csv -c

# Scan a Docker image (requires trivy + sudo)
./training-set-generation/generate_sbom.sh GENERATE_SBOM <image:tag> <output.json>

# Scan all images in a list CSV
./training-set-generation/generate_sbom.sh GENERATE_SBOM_FROM_LIST \
    training-set-generation/image-lists/high-qual.csv \
    training-set-classification/high-qual-vuln-scan/

# Print dataset statistics across all three training buckets
python training-set-classification/compute_statistics.py
```

## ML Pipeline Architecture

The classifier operates on **structured feature vectors** extracted from tool outputs — it never processes raw source code or binary artifacts directly.

**Three training label buckets** (each has a pre-scanned JSON directory and an image-list CSV):
| Label bucket | Directory | Image list CSV |
|---|---|---|
| `ALLOW` candidates | `training-set-classification/high-qual-vuln-scan/` | `training-set-generation/image-lists/high-qual.csv` |
| `WARN`/`BLOCK` candidates | `training-set-classification/aged-stale-vuln-scan/` | `training-set-generation/image-lists/aged-stale.csv` |
| `BLOCK` candidates | `training-set-classification/known-vuln-scan/` | `training-set-generation/image-lists/known-vuln.csv` |

**Feature vector** (11 features, all from CycloneDX JSON produced by Trivy):
- `total_dependency_count`, `vuln_total`, `critical_cve_count`, `high_cve_count`, `cvss_ge_7_count`, `max_cvss`, `unique_cwe_count`, `top25_cwe_count`
- `semgrep_total`, `semgrep_high_count` — externally injected (default 0; Semgrep integration not yet built)
- `base_image_age_days` — two-tier: label fallback chain → Docker Hub public API

**Classification** is currently rule-based (`BLOCK_THRESHOLDS` / `WARN_THRESHOLDS` constants in `sbom_extractor.py`). The Decision Tree model training step has not been implemented yet. Threshold rationale is in `ml-classifier/training-set-classification/dataset-statistics.md`.

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
