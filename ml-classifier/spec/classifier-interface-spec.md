# ML Classifier Interface Specification

**Component:** `src/classifier/` — Risk-Aware Supply Chain Security
**Version:** 1.1
**Author:** Alexander Castro
**Date:** 2026-04-11

---

## 1. Overview

The ML classifier (`src/classifier/`) provides a Decision Tree-based risk classification layer for the supply chain security pipeline. It supplements — but does not replace — the rule-based classifier already present in `sbom_extractor.classify_metric()`.

### When to use each classifier

| Classifier | Location | Use when |
|---|---|---|
| `sbom_extractor.classify_metric(metric)` | `src/classifier/sbom_extractor.py` | You need a deterministic, auditable decision with no model dependency |
| `classifier.Predictor.predict(metric)` | `src/classifier/predictor.py` | A trained model is available and you want a decision informed by compound feature signals |

Both classifiers consume the same `SecurityMetric` feature vector and produce the same three labels (`ALLOW`, `WARN`, `BLOCK`), but they may disagree on individual images. The rule-based classifier is always the authoritative fallback when no model has been trained.

**The ML classifier is not autonomous.** Final deployment authority belongs to designated human reviewers, who retain an override and retraining feedback loop.

---

## 2. Feature Vector Schema

The `SecurityMetric` dataclass (defined in `src/classifier/sbom_extractor.py`) is the canonical feature vector. All 9 feature fields are `float`. The `scan_file` field is metadata, not a feature.

| Field | Type | Units | Valid Range | Source in CycloneDX SBOM |
|---|---|---|---|---|
| `total_dependency_count` | float | count | ≥ 0 | `len(sbom["components"])` |
| `vuln_total` | float | count | ≥ 0 | `len(sbom["vulnerabilities"])` |
| `critical_cve_count` | float | count | ≥ 0 | Vulns where highest severity rating ≥ CRITICAL (weight 5) |
| `high_cve_count` | float | count | ≥ 0 | Vulns where highest severity rating ≥ HIGH (weight 4, includes criticals) |
| `cvss_ge_7_count` | float | count | ≥ 0 | Vulns with any CVSS score ≥ 7.0 |
| `max_cvss` | float | CVSS score | 0.0 – 10.0 | Maximum CVSS score across all vulnerability ratings |
| `unique_cwe_count` | float | count | ≥ 0 | Number of distinct CWE IDs across all vulnerabilities |
| `top25_cwe_count` | float | count | ≥ 0 | Number of vulns with ≥ 1 CWE in MITRE Top 25 (2025) |
| `base_image_age_days` | float | days | ≥ 0 | Days between base image build date and scan timestamp |

### Notes on `base_image_age_days`

Extraction uses a two-tier strategy:

1. **Label fallback chain** — checks `aquasecurity:trivy:Labels:build-date`, `org.opencontainers.image.created`, `org.label-schema.build-date`, and `com.docker.dhi.created` in `.metadata.component.properties`.
2. **Docker Hub API** — if no label resolves, queries `hub.docker.com/v2/repositories/{namespace}/{image}/tags/{tag}` for `last_updated` (5-second timeout).

Returns `0.0` when both tiers fail or when the tag was republished after scanning. A `0.0` value suppresses the age-based BLOCK and WARN signals — treat it as "age unknown," not as evidence of freshness.

### The `FEATURES` constant

`sbom_extractor.FEATURES` is a `List[str]` of the 9 feature field names in the exact order they appear as `SecurityMetric` dataclass fields. It is the single source of truth for feature ordering across training, persistence, and prediction. Consumers must not hardcode this list.

---

## 3. Training Interface

### 3.1 Inputs

#### Data inputs

| Argument | Type | Description |
|---|---|---|
| `manifests_dir` | `Path` | Directory containing the three manifest CSV files |
| `data_root` | `Path` | Root directory containing SBOM JSON files (organised by bucket subdirectory) |

**Manifest CSV format** — one row per image:
```
image:tag,output-filename.json
```

**Expected manifest filenames:**

| File | Bucket name | Bucket-level label |
|---|---|---|
| `high-qual.csv` | `high-qual` | ALLOW |
| `aged-stale.csv` | `aged-stale` | WARN |
| `known-vuln.csv` | `known-vuln` | BLOCK |

**SBOM JSON search order** (for each filename in the manifest):
1. `data_root/{bucket_name}/{filename}` — canonical layout
2. `data_root/{filename}` — flat layout
3. Recursive glob under `data_root` — fallback

Missing files emit a `WARNING` log record via the `classifier.data_loader` logger and are skipped; they do not abort the load.

#### Hyperparameters (`TrainingConfig` defaults)

| Parameter | Default | Description |
|---|---|---|
| `criterion` | `"gini"` | Impurity measure for splitting |
| `max_depth` | `5` | Maximum tree depth (kept shallow for interpretability) |
| `min_samples_split` | `4` | Minimum samples to split an internal node |
| `min_samples_leaf` | `2` | Minimum samples at a leaf node |
| `class_weight` | `"balanced"` | Compensates for class imbalance across the three buckets |
| `random_state` | `42` | Seed for reproducibility |
| `test_size` | `0.20` | Fraction held out for testing |
| `cv_folds` | `5` | Number of stratified cross-validation folds |

### 3.2 Label Assignment

Training labels are derived from `sbom_extractor.classify_metric()` (rule-based thresholds), **not** from the bucket a scan came from. The bucket-level label (`bucket_label` column) reflects sourcing intent; the rule label (`rule_label` column) is the actual training target.

**Circular labeling caveat:** Because the training labels are generated by the same threshold logic that the rule-based classifier uses, the Decision Tree tends to reproduce the rules rather than discover new decision boundaries. See `analysis/rule-based-vs-decision-tree.md` for a full discussion. This limitation breaks as dataset size grows beyond ~1,400 images where manual expert labeling becomes feasible.

### 3.3 Artifact Contracts

All artifacts are written to `output_dir`. The three pkl files form an **inseparable set** — loading any pkl from one training run with pkls from a different run produces undefined behavior.

| Artifact | Filename | Format | Content |
|---|---|---|---|
| Trained model | `decision_tree_model.pkl` | joblib | `sklearn.tree.DecisionTreeClassifier` fitted on training split |
| Label encoder | `label_encoder.pkl` | joblib | `sklearn.preprocessing.LabelEncoder` fitted on `{"ALLOW", "WARN", "BLOCK"}` |
| Feature names | `feature_names.pkl` | joblib | `List[str]` of length 9 — same order the model was trained on |
| Text report | `classification_report.txt` | UTF-8 text | Dataset summary, accuracy, CV scores, sklearn classification report, decision tree rules |
| Confusion matrix | `confusion_matrix.png` | PNG, 150 dpi | Heatmap of test-set predictions vs. ground truth |
| Decision tree | `decision_tree.png` | PNG, 150 dpi | Rendered tree (max_depth=5) with filled nodes and impurity values |
| Feature importances | `feature_importances.png` | PNG, 150 dpi | Bar chart sorted descending by Gini importance |
| Correlation matrix | `feature_correlation_matrix.png` | PNG, 150 dpi | Lower-triangle Pearson correlation heatmap (full dataset) |

---

## 4. Prediction Interface

### 4.1 Inputs

Two accepted input forms:

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
    "base_image_age_days": 2100.0,
})
```

Missing keys in the dict default to `0.0`.

### 4.2 Output — `PredictionResult`

```python
@dataclass
class PredictionResult:
    label: str               # "ALLOW", "WARN", or "BLOCK"
    confidence: Optional[float]  # predict_proba score for the predicted class; None if unavailable
```

`confidence` is the Decision Tree's `predict_proba()` score for the winning class. For shallow trees, this is the fraction of training samples of that class in the leaf node. It is **not** a calibrated probability.

### 4.3 Distinction from rule-based classification

```
sbom_extractor.classify_metric(metric)
    → deterministic, no model required, based on explicit threshold constants
    → result is reproducible and auditable without any pkl files

classifier.Predictor.predict(metric)
    → requires decision_tree_model.pkl, label_encoder.pkl, feature_names.pkl
    → result depends on training data and random_state
    → may capture compound-signal patterns that the rule-based approach misses
```

When the two classifiers disagree, neither is automatically authoritative. Document both results in the audit trail and escalate to a human reviewer.

---

## 5. CLI Interface

The toolkit ships as a single wheel with **two separate entry points**. They serve different users and are intentionally independent — each has only the flags relevant to its workflow.

| Entry point | Intended user | Registered in `pyproject.toml` |
|---|---|---|
| `risk-classifier-train` | Data scientist / model developer | `classifier.cli:main_train` |
| `risk-classifier-predict` | CI/CD pipeline / security engineer | `classifier.cli:main_predict` |

### 5.1 `risk-classifier-train`

```
risk-classifier-train --manifests-dir DIR --data-root DIR [options]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--manifests-dir` | Path (required) | — | Directory containing the three manifest CSV files |
| `--data-root` | Path (required) | — | Root directory with SBOM JSON files |
| `--output-dir` | Path | `analysis/` | Where to write pkl files, PNGs, and the text report |
| `--max-depth` | int | `5` | Maximum Decision Tree depth |
| `--min-samples-split` | int | `4` | Minimum samples to split a node |
| `--min-samples-leaf` | int | `2` | Minimum samples at a leaf |
| `--test-size` | float | `0.20` | Held-out test fraction |
| `--random-state` | int | `42` | Random seed |
| `--no-plots` | flag | `False` | Skip saving visualization PNGs |
| `--no-report` | flag | `False` | Skip saving the text report |
| `--log-level` | `DEBUG`\|`INFO`\|`WARNING`\|`ERROR` | `INFO` | Logging verbosity; INFO is sufficient for auditing, DEBUG shows per-feature extraction detail |
| `--log-file` | Path | (none) | Also write log records to this file in addition to stdout |

### 5.2 `risk-classifier-predict`

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
| `--log-file` | Path | (none) | Also write log records to this file in addition to stdout |

`--sbom` accepts both a single `.json` file and a directory. Directory mode processes all `*.json` files found.

### 5.3 Logging

Both commands emit structured log records to **stdout** (not stderr) via Python's `logging` module. The root logger is `classifier`; per-module loggers follow the `classifier.<module>` hierarchy (e.g. `classifier.data_loader`, `classifier.sbom_extractor`).

Log format: `%(asctime)s [%(levelname)s] %(name)s: %(message)s`

**INFO records relevant to auditing:**
- Every ALLOW/WARN/BLOCK classification decision with the triggering field, its value, and the threshold
- Every ML prediction with `scan_file`, label, and confidence
- Dataset load counts per bucket
- Training split sizes, hyperparameters, test accuracy, and CV accuracy

**DEBUG records relevant to development:**
- Per-feature extracted value for each SBOM
- Per-fold CV scores
- Docker Hub API URL and timeout outcomes
- Date parse format matched

### 5.4 Usage examples

**Minimum viable training:**
```bash
risk-classifier-train \
    --manifests-dir data/image-lists/ \
    --data-root data/scans/
```

**Training with audit log written to file:**
```bash
risk-classifier-train \
    --manifests-dir data/image-lists/ \
    --data-root data/scans/ \
    --output-dir analysis/ \
    --log-file analysis/train-audit.log
```

**Predict from a single SBOM (JSON output to stdout):**
```bash
risk-classifier-predict \
    --sbom data/scans/high-qual/alpine-3.18.json \
    --artifact-dir analysis/
```

**Predict from a directory, write CSV to file, with audit log:**
```bash
risk-classifier-predict \
    --sbom data/scans/high-qual/ \
    --artifact-dir analysis/ \
    --format csv \
    --output results.csv \
    --log-file pipeline-audit.log
```

---

## 6. Development Workflow

The `Makefile` in `ml-classifier/` provides targets for all common development tasks. Run `make help` for a summary.

| Target | Command | Description |
|---|---|---|
| `make install` | `./setup.sh` | Create `.venv` and install the package in editable mode with dev extras |
| `make test` | `pytest tests/ -v` | Run the full test suite |
| `make train` | `risk-classifier-train ...` | Train on all three buckets; artifacts written to `analysis/runs/YYYYMMDD-HHMMSS/` |
| `make build` | `python -m build` | Build a source distribution and wheel into `dist/` |
| `make clean` | — | Remove `dist/`, `build/`, `*.egg-info`, and `__pycache__` trees |

**Prerequisite for all `risk-classifier` commands:** the package must be installed (`make install` or `pip install -e .`) and the venv must be active (`source .venv/bin/activate`).

---

## 7. Constraints and Limitations

- **All three manifests required for a balanced training set.** Missing any single bucket degrades class balance. Training continues with available data but `class_weight="balanced"` only partially compensates.

- **Current dataset is 143 images.** The Decision Tree trained on this dataset tends to reproduce the rule-based thresholds rather than discover new boundaries. See `analysis/rule-based-vs-decision-tree.md`. Meaningful ML generalization begins around 1,400+ images with independent human labels.

- **MITRE Top 25 CWEs are the 2025 edition**, hardcoded in `sbom_extractor.TOP_25_CWES`. This list must be updated manually when MITRE publishes a new annual list.

- **`base_image_age_days` returns `0.0` on extraction failure.** This suppresses the age-based BLOCK signal for images where the tag was republished after scanning or where no date metadata is available. Do not interpret `0.0` as evidence of a fresh image.

- **The three pkl artifacts are version-coupled.** `decision_tree_model.pkl`, `label_encoder.pkl`, and `feature_names.pkl` must always be loaded together from the same training run. Mixing artifacts from different runs produces undefined predictions.

- **Prediction is not autonomous.** Per the project's human-in-the-loop design, ML predictions must be logged with the full feature vector, model version, confidence score, and the enforcement action taken. Human reviewers retain override authority, and override events should be retained for future retraining.
