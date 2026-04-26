# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Environment Setup

```bash
# Create virtualenv and install package in editable mode (uses highest available Python 3.x)
make install        # runs setup.sh, equivalent to: ./setup.sh

# Activate the virtualenv for subsequent commands
source .venv/bin/activate
```

The virtual environment is Python 3.9+ (`.venv/`). Dependencies are declared in `pyproject.toml`. Runtime deps: `pandas`, `scikit-learn`, `joblib`, `numpy`, `matplotlib`, `seaborn`. Dev extras (installed by `setup.sh` / `make install`): `pytest`. Optional LLM extras:
- `pip install -e '.[gemini]'` — Google Gemini SDK (`google-genai>=1.0`) — **preferred; used for current labels**
- `pip install -e '.[llm]'` — Anthropic SDK (`anthropic>=0.25`)

## Running the SBOM Extractor (standalone CLI)

The extractor CLI lives at `src/classifier/sbom_extractor.py` and can be invoked directly as a script.

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

Three separate entry points are provided — labeling, training, and prediction.

```bash
# --- Labeling (run once after scanning, or after threshold/prompt changes) ---

# Threshold mode (rule-based, default) — writes per-bucket CSVs to data/labels/
make label

# Or run directly:
risk-classifier-label \
    --manifests-dir data/image-lists/ \
    --data-root data/scans/ \
    --output-dir data/labels/
# Writes: data/labels/high-qual-labels.csv
#         data/labels/aged-stale-labels.csv
#         data/labels/known-vuln-labels.csv

# LLM mode — Gemini backend (preferred; requires GEMINI_API_KEY or --llm-api-key)
# gemini-2.5-flash was used to generate the current data/labels/ CSVs
make label-llm-gemini
# Override model or prompt:
make label-llm-gemini GEMINI_MODEL=gemini-1.5-pro
make label-llm-gemini SYSTEM_PROMPT=config/system-prompt-v2.md

# LLM mode — Anthropic backend (requires ANTHROPIC_API_KEY or --llm-api-key)
make label-llm-anthropic
make label-llm-anthropic LLM_MODEL=claude-haiku-4-5-20251001

# Or run directly (llm mode, Gemini):
risk-classifier-label \
    --manifests-dir data/image-lists/ \
    --data-root data/scans/ \
    --output-dir data/labels/ \
    --labeler-mode llm \
    --llm-provider gemini \
    --llm-model gemini-2.5-flash \
    --system-prompt config/system-prompt-v2.md

# --- Training (model developer / data scientist) ---

# Train using default paths — artifacts written to training-runs/YYYYMMDD-HHMMSS/
make train

# Train the Decision Tree from pre-labeled CSVs
risk-classifier-train \
    --labels-dir data/labels/ \
    --output-dir training-runs/

# --- Prediction (CI/CD pipeline / security engineer) ---

# Predict from a single SBOM file (requires trained artifacts in analysis/)
risk-classifier-predict \
    --sbom data/scans/high-qual/alpine-3.18.json \
    --artifact-dir analysis/ \
    --format json

# Predict from a directory of SBOMs, write CSV to file
risk-classifier-predict \
    --sbom data/scans/high-qual/ \
    --artifact-dir analysis/ \
    --format csv \
    --output results.csv
```

## Running Tests

```bash
make test                    # shorthand
python -m pytest tests/ -v   # equivalent
```

Tests live in `tests/` and cover `data_loader`, `trainer`, `predictor`, and `reporting`. `tests/conftest.py` adds `src/` to `sys.path` as a fallback for uninstalled environments. After `pip install -e '.[dev]'`, the `classifier` package is importable via site-packages and this manipulation is a no-op.

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
- Features (8): `total_dependency_count`, `vuln_total`, `critical_cve_count`, `high_cve_count`, `cvss_ge_7_count`, `max_cvss`, `unique_cwe_count`, `top25_cwe_count`
- SAST/Semgrep features (`semgrep_total`, `semgrep_high_count`) were removed from current scope; rationale is in `research/ML_model/semgrep-feature-analysis.md`
- Severity ratings use the highest rating across all sources per vulnerability (not NVD-only)
- Top 25 CWEs reference the MITRE 2025 list hardcoded in `TOP_25_CWES`
- `FEATURES` list is the single source of truth for feature ordering across training and prediction

**Stage 3 — Labeling** (`src/classifier/sbom_extractor.py`, `src/classifier/llm_labeler.py`, `src/classifier/backends/`)

Two modes, both return a `LabelResult(label, justification, confidence)`:

- **Threshold mode** (`classify_metric_threshold`) — rule-based via `BLOCK_THRESHOLDS` / `WARN_THRESHOLDS`; fast and fully deterministic. `BLOCK` is evaluated before `WARN`. Legacy `classify_metric()` still exists for backwards compat (returns a plain `str`).
- **LLM mode** (`classify_metric_llm`) — sends only the 8-feature vector (not raw SBOM content) to an LLM backend. The system prompt is loaded from a versioned file (`config/system-prompt-vN.txt`). Backends live in `src/classifier/backends/`: `GeminiBackend` (preferred) and `AnthropicBackend`. The `llm_labeler.py` module owns prompt loading (`load_system_prompt`), user-message construction (`build_user_message`), and response parsing (`parse_llm_response`) with a safe fallback of `WARN` on any parse failure. **The current `data/labels/` CSVs were generated with `gemini-2.5-flash`.**

**Stage 3b — Label Persistence** (`src/classifier/data_loader.py`, `risk-classifier-label`)
- `write_labels_csv(df, path)` — persists a labeled bucket DataFrame to CSV so labels are frozen at labeling time
- `risk-classifier-label` CLI command writes `{bucket}-labels.csv` per bucket to `--output-dir` (default: `data/labels/`)
- Training (`load_bucket`) consumes these CSVs via `--labels-dir` to skip live feature extraction and labeling on every run
- Label drift (threshold changes, prompt changes) becomes a visible `git diff` on the label CSV rather than a silent accuracy drop

**Stage 4 — ML Training and Prediction** (`src/classifier/`)
- `data_loader.py` — reads bucket manifests, optionally reads pre-labeled CSVs, calls the extractor for each SBOM, builds a labeled DataFrame
- `trainer.py` (`TrainingConfig`, `TrainingResult`, `Trainer`) — hyperparameter dataclass, training output bundle with visualization/reporting methods, and the `Trainer` class that fits a `DecisionTreeClassifier` and runs stratified K-fold CV
- `predictor.py` (`Predictor`) — loads saved pkl artifacts and exposes `predict(metric)` / `predict_from_dict(dict)`
- `cli.py` — `label`, `train`, and `predict` subcommands; registered as separate console scripts via `pyproject.toml`

## Package Layout

```
pyproject.toml               # Build configuration, dependencies, and three console script entry points
                             # Optional extras: [llm] = anthropic, [gemini] = google-genai
Makefile                     # install / label / label-llm-anthropic / label-llm-gemini / test / train / build / clean targets
config/
  system-prompt-v1.md       # Versioned LLM labeling system prompt (used by llm mode)
src/
  classifier/
    __init__.py              # Public API: Trainer, Predictor, TrainingConfig, TrainingResult,
                             #             SecurityMetric, FEATURES, classify_metric,
                             #             build_security_metric_from_sbom
    sbom_extractor.py        # Feature extraction, SecurityMetric/LabelResult dataclasses,
                             # classify_metric_threshold(), classify_metric_llm()
    llm_labeler.py           # load_system_prompt(), build_user_message(), parse_llm_response()
    backends/
      __init__.py
      anthropic_backend.py   # AnthropicBackend — wraps anthropic SDK
      gemini_backend.py      # GeminiBackend — wraps google-genai SDK
    data_loader.py           # Dataset loading from bucket manifests
    trainer.py               # TrainingConfig, TrainingResult, Trainer, visualization and reporting functions
    predictor.py             # ML inference from saved artifacts
    cli.py                   # Label, train, and predict CLI entry points
tests/
  conftest.py                # sys.path fallback for uninstalled environments; no-op after editable install
  test_data_loader.py
  test_trainer.py
  test_predictor.py
  test_reporting.py
```

## Key Import Note

`cli.py` uses absolute imports (`from classifier import ...`) and is registered as the `risk-classifier` console script via `pyproject.toml`. The package must be installed (`pip install -e .`) before `risk-classifier` is available on PATH.
