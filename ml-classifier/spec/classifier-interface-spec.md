# ML Classifier Interface Specification

**Component:** `src/classifier/` — Risk-Aware Supply Chain Security
**Version:** 1.2
**Author:** Alexander Castro
**Date:** 2026-04-26

---

## 1. Overview

The ML classifier (`src/classifier/`) provides a Decision Tree-based risk classification layer for the supply chain security pipeline. It supplements — but does not replace — the rule-based classifier in `sbom_extractor.classify_metric_threshold()`.

### When to use each classifier

| Classifier | Location | Use when |
|---|---|---|
| `sbom_extractor.classify_metric_threshold(metric)` | `src/classifier/sbom_extractor.py` | You need a deterministic, auditable decision with no model dependency |
| `classifier.Predictor.predict(metric)` | `src/classifier/predictor.py` | A trained model is available and you want a decision informed by compound feature signals |

Both classifiers consume the same `SecurityMetric` feature vector and produce the same three labels (`ALLOW`, `WARN`, `BLOCK`), but may disagree on individual images. The rule-based classifier is always the authoritative fallback when no model has been trained.

**The ML classifier is not autonomous.** Final deployment authority belongs to designated human reviewers, who retain an override and retraining feedback loop.

---

## 2. Feature Vector Schema

The `SecurityMetric` dataclass (defined in `src/classifier/sbom_extractor.py`) is the canonical feature vector. All 8 feature fields are `float`. The `scan_file` field is metadata, not a feature.

| Field | Type | Units | Valid Range | Source in CycloneDX SBOM |
|---|---|---|---|---|
| `total_dependency_count` | float | count | ≥ 0 | `len(sbom["components"])` |
| `vuln_total` | float | count | ≥ 0 | `len(sbom["vulnerabilities"])` |
| `critical_cve_count` | float | count | ≥ 0 | Vulns where highest severity rating = CRITICAL |
| `high_cve_count` | float | count | ≥ 0 | Vulns where highest severity rating = HIGH |
| `cvss_ge_7_count` | float | count | ≥ 0 | Vulns with any CVSS score ≥ 7.0 |
| `max_cvss` | float | CVSS score | 0.0 – 10.0 | Maximum CVSS score across all vulnerability ratings |
| `unique_cwe_count` | float | count | ≥ 0 | Number of distinct CWE IDs across all vulnerabilities |
| `top25_cwe_count` | float | count | ≥ 0 | Number of vulns with ≥ 1 CWE in MITRE Top 25 (2025) |

### The `FEATURES` constant

`sbom_extractor.FEATURES` is a `List[str]` of the 8 feature field names in the exact order they appear as `SecurityMetric` dataclass fields. It is the single source of truth for feature ordering across labeling, training, and prediction. Consumers must not hardcode this list.

---

## 3. Labeling Interface

Labeling is a separate pipeline stage that runs **before** training. It produces label CSVs that training then consumes. Labels are frozen at labeling time so that prompt changes, threshold changes, or re-runs produce a visible `git diff` rather than silent drift.

### 3.1 Labeling modes

Two modes are supported via the `--labeler-mode` flag on `risk-classifier-label`:

| Mode | Flag | Label source | Deterministic | Current default |
|---|---|---|---|---|
| Threshold | `--labeler-mode threshold` | `classify_metric_threshold()` — rule-based via `BLOCK_THRESHOLDS` / `WARN_THRESHOLDS` | Yes | No |
| LLM | `--labeler-mode llm` | LLM backend (Gemini or Anthropic) + versioned system prompt | Near-deterministic (temperature=0) | **Yes** |

**LLM mode is the current default** and was used to generate the `data/labels/` CSVs that all model versions from v0.0.5 onward were trained on. `gemini-2.5-flash` + `config/system-prompt-v3.md` is the active configuration.

### 3.2 LLM labeling

The LLM receives only the 8-feature vector (not raw SBOM content) and returns a `LabelResult(label, justification, confidence)`. Backends live in `src/classifier/backends/`:

- `GeminiBackend` — wraps `google-genai`; requires `GEMINI_API_KEY` or `--llm-api-key`
- `AnthropicBackend` — wraps `anthropic` SDK; requires `ANTHROPIC_API_KEY` or `--llm-api-key`

Both backends use `temperature=0`. Parse failures fall back to `WARN` with `confidence="low"` — WARN is the safest fallback: it flags for human review without silently approving or hard-blocking.

The system prompt at `config/system-prompt-vN.md` plays the role that `BLOCK_THRESHOLDS` / `WARN_THRESHOLDS` play in threshold mode. It must be treated as immutable for a given model version. Changes to the prompt trigger a full re-labeling run and a new model version.

For system prompt evolution history (v1 → v2 → v3), see `analysis/llm-labeling-proposal.md`.

### 3.3 Label CSV schema

Each label CSV written by `write_labels_csv()` contains:

| Column | Description |
|---|---|
| `scan_file` | Path to the source SBOM JSON file |
| `image` | Image name and tag |
| `bucket` | Bucket name (`high-qual`, `aged-stale`, `known-vuln`) |
| `bucket_label` | Bucket-level intent label (`ALLOW`, `WARN`, `BLOCK`) |
| `rule_label` | **Actual training target** — assigned by the labeler (threshold or LLM) |
| *(8 feature columns)* | Feature values at scan time |
| `justification` | LLM-mode only — natural-language reasoning for the label |
| `confidence` | LLM-mode only — `"high"`, `"medium"`, or `"low"` |

**`rule_label` is the training target**, not `bucket_label`. The bucket reflects sourcing intent; the rule label reflects the labeler's assessment of the feature values. These frequently diverge — see `analysis/llm-labeling-proposal.md` for the bucket-label assumption analysis.

### 3.4 Output files

`risk-classifier-label` writes one CSV per bucket to `--output-dir`:

| File | Bucket |
|---|---|
| `high-qual-labels.csv` | `high-qual` |
| `aged-stale-labels.csv` | `aged-stale` |
| `known-vuln-labels.csv` | `known-vuln` |

---

## 4. Training Interface

### 4.1 Inputs

Training consumes the pre-labeled CSVs produced by `risk-classifier-label`. It does not read SBOM JSON files or manifest CSVs — all required information is already in the label CSVs.

| Argument | Type | Description |
|---|---|---|
| `labels_dir` | `Path` | Directory containing the three pre-labeled bucket CSVs |

Each CSV must contain `REQUIRED_COLUMNS`: `scan_file, image, bucket, bucket_label, rule_label` + the 8 feature fields. Missing CSVs emit a `WARNING` and that bucket is skipped. All three missing raises `RuntimeError`.

### 4.2 Hyperparameters (`TrainingConfig`)

CLI defaults reflect the current Makefile configuration. `TrainingConfig` dataclass defaults may differ — always prefer the Makefile values when running `make train`.

| Parameter | `TrainingConfig` default | `make train` default | Description |
|---|---|---|---|
| `criterion` | `"gini"` | `"gini"` | Impurity measure for splitting |
| `max_depth` | `5` | **`4`** | Maximum tree depth |
| `min_samples_split` | `4` | `4` | Minimum samples to split a node |
| `min_samples_leaf` | `2` | `2` | Minimum samples at a leaf |
| `class_weight` | `"balanced"` | **`{"ALLOW":4,"WARN":2,"BLOCK":3}`** | Class weight scheme |
| `random_state` | `42` | `42` | Seed for reproducibility |
| `test_size` | `0.20` | `0.20` | Fraction held out for testing |
| `cv_folds` | `5` | `5` | Number of stratified CV folds |

The `class_weight` dict form (`{"ALLOW":4,"WARN":2,"BLOCK":3}`) is passed as a JSON string via `--class-weight`. The CLI parses and validates it before constructing `TrainingConfig`.

### 4.3 Escalation policy

The escalation policy applies at **both** prediction time and during training evaluation, so reported metrics reflect what the pipeline actually produces in deployment:

- WARN predictions with `predict_proba(WARN) < 0.75` are escalated to BLOCK
- BLOCK is never downgraded regardless of confidence

The `WARN_CONFIDENCE_THRESHOLD` constant (`0.75`) is defined in `predictor.py`. CV and test-set accuracy in `classification_report.txt` are computed after escalation is applied.

### 4.4 Artifact contracts

All artifacts are written to `output_dir`. The three pkl files form an **inseparable set** — mixing artifacts from different training runs produces undefined behavior.

| Artifact | Filename | Format | Content |
|---|---|---|---|
| Trained model | `decision_tree_model.pkl` | joblib | `sklearn.tree.DecisionTreeClassifier` fitted on training split |
| Label encoder | `label_encoder.pkl` | joblib | `sklearn.preprocessing.LabelEncoder` fitted on `{"ALLOW","WARN","BLOCK"}` |
| Feature names | `feature_names.pkl` | joblib | `List[str]` of length 8 — same order as training |
| Text report | `classification_report.txt` | UTF-8 text | Dataset summary, hyperparameters, accuracy, CV scores, sklearn report, decision tree rules, escalation summary |
| Confusion matrix | `confusion_matrix.png` | PNG, 150 dpi | Heatmap of test-set predictions vs. ground truth (post-escalation) |
| Decision tree | `decision_tree.png` | PNG, 150 dpi | Rendered tree with filled nodes and impurity values |
| Feature importances | `feature_importances.png` | PNG, 150 dpi | Bar chart sorted descending by Gini importance |
| Correlation matrix | `feature_correlation_matrix.png` | PNG, 150 dpi | Lower-triangle Pearson correlation heatmap |
| Dataset snapshot (CSV) | `dataset_snapshot.csv` | UTF-8 CSV | Full labeled DataFrame: all metadata columns + 8 features + LLM columns if present |
| Dataset snapshot (JSON) | `dataset_snapshot.json` | UTF-8 JSON | Same content as CSV in records orientation (indented) |

---

## 5. Prediction Interface

### 5.1 Inputs

**Preferred — `SecurityMetric` dataclass:**
```python
from classifier import sbom_extractor as _extractor
from classifier import Predictor

predictor = Predictor(Path("analysis/"))
for file_path, sbom in _extractor.read_path_data(Path("image.json")):
    metric = _extractor.build_security_metric_from_sbom(str(file_path), sbom)
    result = predictor.predict(metric)
```

**Convenience — `Dict[str, float]`:**
```python
result = predictor.predict_from_dict({
    "critical_cve_count": 55.0,
    "top25_cwe_count": 200.0,
})
```

Missing keys in the dict default to `0.0`.

### 5.2 Output — `PredictionResult`

```python
@dataclass
class PredictionResult:
    label: str                    # "ALLOW", "WARN", or "BLOCK" (post-escalation)
    confidence: Optional[float]   # predict_proba score for the predicted class; None if unavailable
    escalated: bool = False       # True when WARN was escalated to BLOCK due to low confidence
```

`confidence` is the Decision Tree's `predict_proba()` score for the winning class — the fraction of training samples of that class in the leaf node. It is **not** a calibrated probability.

`escalated=True` means the model predicted WARN but confidence was below `WARN_CONFIDENCE_THRESHOLD` (0.75), so the label was raised to BLOCK. The `escalated` flag is surfaced in CLI CSV output as the `ml_escalated` column.

### 5.3 Distinction from rule-based classification

```
sbom_extractor.classify_metric_threshold(metric)
    → deterministic, no model required, based on explicit threshold constants
    → reproducible and auditable without pkl files
    → returns LabelResult(label, justification, confidence)

classifier.Predictor.predict(metric)
    → requires decision_tree_model.pkl, label_encoder.pkl, feature_names.pkl
    → result depends on training data, random_state, and escalation policy
    → may capture compound-signal patterns the rule-based approach misses
    → returns PredictionResult(label, confidence, escalated)
```

When the two classifiers disagree, neither is automatically authoritative. Document both results in the audit trail and escalate to a human reviewer.

---

## 6. CLI Interface

Three entry points are registered in `pyproject.toml`. Each serves a distinct user and is intentionally independent.

| Entry point | Intended user | Handler |
|---|---|---|
| `risk-classifier-label` | Data scientist (run once after scanning) | `classifier.cli:main_label` |
| `risk-classifier-train` | Data scientist / model developer | `classifier.cli:main_train` |
| `risk-classifier-predict` | CI/CD pipeline / security engineer | `classifier.cli:main_predict` |

### 6.1 `risk-classifier-label`

```
risk-classifier-label --manifests-dir DIR --data-root DIR --output-dir DIR [options]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--manifests-dir` | Path (required) | — | Directory containing the three image-list CSVs |
| `--data-root` | Path (required) | — | Root directory for SBOM scan files |
| `--output-dir` | Path (required) | — | Directory to write the three `*-labels.csv` files |
| `--labeler-mode` | `threshold`\|`llm` | `threshold` | Labeling strategy |
| `--llm-provider` | `anthropic`\|`gemini` | `anthropic` | LLM backend (only used when `--labeler-mode=llm`) |
| `--llm-model` | str | — | Model name, e.g. `gemini-2.5-flash` or `claude-sonnet-4-6` (required for LLM mode) |
| `--llm-api-key` | str | env var | API key; falls back to `ANTHROPIC_API_KEY` or `GEMINI_API_KEY` |
| `--system-prompt` | Path | — | Path to versioned system prompt file (LLM mode only) |
| `--log-level` | `DEBUG`\|`INFO`\|`WARNING`\|`ERROR` | `INFO` | Logging verbosity |
| `--log-file` | Path | (none) | Also write log records to this file |

**Makefile shorthands:**
```bash
make label                  # threshold mode
make label-llm-gemini       # LLM mode, gemini-2.5-flash + system-prompt-v3.md (preferred)
make label-llm-anthropic    # LLM mode, claude-sonnet-4-6 + system-prompt-v3.md
```

### 6.2 `risk-classifier-train`

```
risk-classifier-train --labels-dir DIR [options]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--labels-dir` | Path (required) | — | Directory containing the three pre-labeled CSVs from `risk-classifier-label` |
| `--output-dir` | Path | `training-runs/` | Where to write pkl artifacts, PNGs, and the text report |
| `--max-depth` | int | `5` | Maximum Decision Tree depth |
| `--min-samples-split` | int | `4` | Minimum samples to split a node |
| `--min-samples-leaf` | int | `2` | Minimum samples at a leaf |
| `--class-weight` | str | `"balanced"` | `"balanced"` or JSON dict e.g. `'{"ALLOW":4,"WARN":2,"BLOCK":3}'` |
| `--test-size` | float | `0.20` | Held-out test fraction |
| `--random-state` | int | `42` | Random seed |
| `--no-plots` | flag | `False` | Skip saving visualization PNGs |
| `--no-report` | flag | `False` | Skip saving the text report |
| `--log-level` | `DEBUG`\|`INFO`\|`WARNING`\|`ERROR` | `INFO` | Logging verbosity |
| `--log-file` | Path | (none) | Also write log records to this file |

### 6.3 `risk-classifier-predict`

```
risk-classifier-predict --sbom PATH --artifact-dir DIR [options]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--sbom` | Path (required) | — | CycloneDX JSON SBOM file or directory of SBOM files |
| `--artifact-dir` | Path (required) | — | Directory containing the three pkl files |
| `--format` | `json`\|`csv` | `json` | Output format |
| `--output` | Path | (stdout) | Write output to this file instead of stdout |
| `--log-level` | `DEBUG`\|`INFO`\|`WARNING`\|`ERROR` | `INFO` | Logging verbosity |
| `--log-file` | Path | (none) | Also write log records to this file |

`--sbom` accepts both a single `.json` file and a directory. Directory mode processes all `*.json` files found.

### 6.4 Logging

All three commands emit structured log records to **stdout** (not stderr) via Python's `logging` module. Root logger: `classifier`; per-module hierarchy: `classifier.<module>`.

Log format: `%(asctime)s [%(levelname)s] %(name)s: %(message)s`

**INFO records relevant to auditing:**
- Every classification decision (threshold or ML) with label, confidence, and `scan_file`
- Escalation events: `scan_file`, original WARN confidence, escalated label
- Dataset load counts per bucket
- Training hyperparameters, split sizes, test accuracy, CV accuracy

**DEBUG records relevant to development:**
- Per-feature extracted value for each SBOM
- Per-fold CV scores

### 6.5 Usage examples

**Label using LLM (Gemini, preferred):**
```bash
make label-llm-gemini   # requires GEMINI_API_KEY
```

**Label using Anthropic:**
```bash
make label-llm-anthropic   # requires ANTHROPIC_API_KEY
```

**Train with current Makefile defaults:**
```bash
make train   # max_depth=4, class_weight={"ALLOW":4,"WARN":2,"BLOCK":3}
```

**Train with explicit hyperparameters:**
```bash
risk-classifier-train \
    --labels-dir data/labels/ \
    --output-dir training-runs/ \
    --max-depth 4 \
    --class-weight '{"ALLOW":4,"WARN":2,"BLOCK":3}' \
    --log-file training-runs/train-audit.log
```

**Predict from a single SBOM:**
```bash
risk-classifier-predict \
    --sbom data/scans/high-qual/alpine-3.18.json \
    --artifact-dir analysis/
```

**Predict from a directory, CSV output:**
```bash
risk-classifier-predict \
    --sbom data/scans/high-qual/ \
    --artifact-dir analysis/ \
    --format csv \
    --output results.csv
```

---

## 7. Development Workflow

The `Makefile` provides targets for all common tasks. Run `make help` for a summary.

| Target | Description |
|---|---|
| `make install` | Create `.venv` and install the package in editable mode with dev extras |
| `make label` | Threshold-mode labeling; writes per-bucket CSVs to `data/labels/` |
| `make label-llm-gemini` | LLM labeling via Gemini (requires `GEMINI_API_KEY`) |
| `make label-llm-anthropic` | LLM labeling via Anthropic (requires `ANTHROPIC_API_KEY`) |
| `make train` | Train on all three label CSVs; artifacts written to `training-runs/YYYYMMDD-HHMMSS/` |
| `make test` | Run the full test suite |
| `make build` | Build a source distribution and wheel into `dist/` |
| `make clean` | Remove `dist/`, `build/`, `*.egg-info`, and `__pycache__` trees |

**Prerequisite for all `risk-classifier` commands:** the package must be installed (`make install`) and the venv active (`source .venv/bin/activate`).

---

## 8. Constraints and Limitations

- **Labels must be generated before training.** `risk-classifier-train` consumes pre-labeled CSVs from `risk-classifier-label`. Running `make train` without first running a label target will use stale or missing CSVs.

- **All three bucket CSVs are required for a balanced training set.** Missing any single bucket degrades class balance. Training continues with available data but the class weight scheme only partially compensates.

- **Current dataset is 371 images.** The WARN class recall plateaus at ~0.75 under current labeling — a data problem, not a hyperparameter problem. The `aged-stale` bucket sources images too severely compromised to populate WARN, leaving WARN predominantly drawn from `high-qual`. See `analysis/llm-labeling-proposal.md`.

- **MITRE Top 25 CWEs are the 2025 edition**, hardcoded in `sbom_extractor.TOP_25_CWES`. This list must be updated manually when MITRE publishes a new annual edition.

- **The three pkl artifacts are version-coupled.** `decision_tree_model.pkl`, `label_encoder.pkl`, and `feature_names.pkl` must always be loaded together from the same training run. Mixing artifacts from different runs produces undefined predictions.

- **Prediction is not autonomous.** ML predictions must be logged with the full feature vector, model version, confidence score, escalation status, and the enforcement action taken. Human reviewers retain override authority; override events should be retained for future retraining.

- **LLM labels are near-deterministic, not fully deterministic.** `temperature=0` minimizes but does not eliminate output variance across API versions and infrastructure changes. The label CSV is the source of truth — re-running the labeler against the same images may produce small differences, which is why labels are committed to version control.
