# Model v0.0.1 — Checkpoint Report

**Date:** 2026-04-14
**Labeling mode:** Threshold-based (rule-based, `classify_metric_threshold`)
**Dataset:** Initial scan batch — 143 images

---

## Overview

Model v0.0.1 is the first trained checkpoint. It establishes the initial pipeline: Trivy SBOM scans → feature extraction → threshold labeling → Decision Tree training. The model achieves strong test accuracy on a small, relatively clean dataset, but the tree structure reveals a fundamental problem: the dominant decision feature is `base_image_age_days`, a temporal proxy for risk rather than a direct vulnerability signal. The model is learning the data collection strategy rather than genuine supply chain risk.

---

## Model Metadata

| Parameter | Value |
|---|---|
| `criterion` | gini |
| `max_depth` | 5 |
| `min_samples_split` | 4 |
| `min_samples_leaf` | 2 |
| `class_weight` | `balanced` |
| `random_state` | 42 |
| `test_size` | 0.20 |
| `cv_folds` | 5 |
| Escalation policy | None |

---

## Feature Set (9 features)

```
total_dependency_count, vuln_total, critical_cve_count, high_cve_count,
cvss_ge_7_count, max_cvss, unique_cwe_count, top25_cwe_count,
base_image_age_days   ← present in this version, removed in v0.0.3
```

---

## Dataset

| Metric | Value |
|---|---|
| Total images | 143 |
| Train / test split | 114 / 29 |
| ALLOW samples | 35 (24.5%) |
| WARN samples | 47 (32.9%) |
| BLOCK samples | 61 (42.7%) |

The label distribution is reasonably balanced across all three classes. This balance is largely a consequence of how the threshold constants were calibrated: `base_image_age_days` thresholds were set to align with bucket identity, so images from `high-qual` tended to be labeled ALLOW, `aged-stale` tended toward WARN, and `known-vuln` toward BLOCK. The apparent balance reflects the bucket sampling strategy, not a discovery about the underlying risk distribution.

---

## Performance

| Metric | Value |
|---|---|
| Test accuracy | **0.9655** |
| CV accuracy | **0.9232 ± 0.0563** (5-fold stratified) |
| CV-test gap | 0.042 |

### Per-Class Results

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| ALLOW | 1.00 | 1.00 | 1.00 | 7 |
| BLOCK | 1.00 | 0.92 | 0.96 | 12 |
| WARN | 0.91 | 1.00 | 0.95 | 10 |
| **macro avg** | **0.97** | **0.97** | **0.97** | **29** |

The 29-sample test set makes per-class metrics unreliable. A single misclassification is worth 3.45 accuracy points. The BLOCK miss (recall=0.92, approximately one image) means one BLOCK was predicted as WARN — a false negative that a security gate should minimize.

---

## Decision Tree

```
|--- base_image_age_days <= 382.00          ← ROOT: age, not vulnerability severity
|   |--- unique_cwe_count <= 41.50
|   |   |--- class: ALLOW
|   |--- unique_cwe_count > 41.50
|   |   |--- class: WARN
|--- base_image_age_days > 382.00
|   |--- critical_cve_count <= 21.50
|   |   |--- base_image_age_days <= 2432.50
|   |   |   |--- top25_cwe_count <= 114.50
|   |   |   |   |--- class: WARN
|   |   |   |--- top25_cwe_count > 114.50
|   |   |   |   |--- class: WARN
|   |   |--- base_image_age_days > 2432.50
|   |   |   |--- class: BLOCK
|   |--- critical_cve_count > 21.50
|   |   |--- top25_cwe_count <= 139.00
|   |   |   |--- base_image_age_days <= 1856.00
|   |   |   |   |--- class: WARN
|   |   |   |--- base_image_age_days > 1856.00
|   |   |   |   |--- class: BLOCK
|   |   |--- top25_cwe_count > 139.00
|   |   |   |--- unique_cwe_count <= 74.00
|   |   |   |   |--- class: BLOCK
|   |   |   |--- unique_cwe_count > 74.00
|   |   |   |   |--- class: BLOCK
```

### Tree Observations

**`base_image_age_days` is the root split and dominates every branch.** The tree uses age as the primary discriminator, then falls back to vulnerability counts only for secondary splits. This is the tree accurately reflecting what the labels encode — images labeled based on their age bucket will inevitably produce a tree rooted in age. But it means the model has not learned to assess vulnerability severity; it has learned to assess image staleness.

**Structural concern: age is not a reliable feature.** `base_image_age_days` is computed from Docker Hub API metadata at scan time, which introduces non-determinism: API timeouts return 0, and image tags may be reassigned after scan. An image scanned twice on different days may receive different age values, flipping it across the 382-day decision boundary. This creates label instability that is invisible in a single training run.

**The top-right subtree (age > 2432) resolves entirely to BLOCK** regardless of critical CVE count or top25 CWE count. This means any image older than ~6.6 years is always classified BLOCK — again, a consequence of the labeling strategy rather than vulnerability evidence.

---

## Known Limitations and What Changed Next

**Small dataset (143 images).** CV variance of ±5.6% indicates high sensitivity to which images land in each fold. With only ~29 images per test fold, a single misclassification swings accuracy by 3.5 points. The estimate cannot be trusted at this scale.

**`base_image_age_days` dominates the model.** The feature introduces non-determinism, encodes the data collection strategy rather than risk, and will not generalize to images outside the age range of the training set. It needs to be removed.

**No escalation policy.** Low-confidence WARN predictions are not escalated. A model that incorrectly predicts WARN for a BLOCK-level image will pass that image through without any safety net.

**→ v0.0.2** addresses the dataset size concern by expanding to 371 images.
**→ v0.0.3** removes `base_image_age_days` from the feature set entirely.
**→ v0.0.4** introduces the WARN confidence escalation policy.
