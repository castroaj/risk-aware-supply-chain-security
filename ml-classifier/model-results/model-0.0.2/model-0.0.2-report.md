# Model v0.0.2 — Checkpoint Report

**Date:** 2026-04-15
**Labeling mode:** Threshold-based (rule-based, `classify_metric_threshold`)
**Dataset:** Expanded scan batch — 371 images (2.6× from v0.0.1)

---

## Overview

Model v0.0.2 is a dataset expansion checkpoint. The primary objective was to reduce the CV variance identified in v0.0.1 (±5.6%) by adding images across all three buckets — reaching 371 images from 143. The hyperparameter configuration is unchanged. The expansion achieves its goal: CV variance drops to ±2.3%, and the tree root shifts from `base_image_age_days` to `top25_cwe_count`, indicating the model found a stronger vulnerability-based discriminator once it had enough examples to learn from. Both of these are genuine improvements, but `base_image_age_days` remains in the feature set and continues to appear throughout the tree.

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
base_image_age_days   ← still present, removed in v0.0.3
```

---

## Dataset

| Metric | Value |
|---|---|
| Total images | 371 (from 143 in v0.0.1) |
| Train / test split | 296 / 75 |
| ALLOW samples | 96 (25.9%) |
| WARN samples | 151 (40.7%) |
| BLOCK samples | 124 (33.4%) |

The class distribution shifted from v0.0.1 (ALLOW=35, BLOCK=61, WARN=47) primarily because new images were added to all three buckets. The `balanced` class weight setting adjusts automatically for the new distribution. WARN is now the plurality class, reflecting that many of the newly scanned images — even those in the `aged-stale` bucket — fell into the moderate-severity band under threshold labeling.

---

## Performance

| Metric | Value |
|---|---|
| Test accuracy | **0.9600** |
| CV accuracy | **0.9570 ± 0.0229** (5-fold stratified) |
| CV-test gap | 0.003 |

### Per-Class Results

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| ALLOW | 0.90 | 0.95 | 0.92 | 19 |
| BLOCK | 1.00 | 1.00 | 1.00 | 25 |
| WARN | 0.97 | 0.94 | 0.95 | 31 |
| **weighted avg** | **0.96** | **0.96** | **0.96** | **75** |

### Key Improvement vs v0.0.1

| Metric | v0.0.1 | v0.0.2 | Change |
|---|---|---|---|
| Test accuracy | 0.9655 | 0.9600 | −0.006 |
| CV accuracy (mean) | 0.9232 | 0.9570 | **+0.034** |
| CV std deviation | ±0.0563 | **±0.0229** | **−0.033** |
| BLOCK recall | 0.92 | **1.00** | +0.08 |

The small test accuracy drop (0.97 → 0.96) is not a regression. The v0.0.1 test set had 29 samples; v0.0.2 has 75. A single misclassification now costs 1.3 accuracy points instead of 3.5. The CV estimate is the more reliable signal: it improved by 3.4 points while the standard deviation nearly halved. This is the expected signature of a better-generalized model — higher mean performance with lower variance across folds.

BLOCK recall reaching 1.00 is the most operationally significant improvement. The baseline missed approximately 1-in-8 BLOCK images; v0.0.2 missed none across a 25-sample BLOCK test partition.

---

## Decision Tree

```
|--- top25_cwe_count <= 143.00              ← ROOT shifted from age to CWE coverage
|   |--- high_cve_count <= 31.50
|   |   |--- base_image_age_days <= 368.50
|   |   |   |--- unique_cwe_count <= 40.00
|   |   |   |   |--- class: ALLOW
|   |   |   |--- unique_cwe_count > 40.00
|   |   |   |   |--- class: WARN
|   |   |--- base_image_age_days > 368.50
|   |   |   |--- top25_cwe_count <= 0.50
|   |   |   |   |--- class: WARN
|   |   |   |--- top25_cwe_count > 0.50
|   |   |   |   |--- class: WARN
|   |--- high_cve_count > 31.50
|   |   |--- critical_cve_count <= 49.00
|   |   |   |--- unique_cwe_count <= 39.00
|   |   |   |   |--- base_image_age_days <= 327.50
|   |   |   |   |   |--- class: ALLOW
|   |   |   |   |--- base_image_age_days > 327.50
|   |   |   |   |   |--- class: WARN
|   |   |   |--- unique_cwe_count > 39.00
|   |   |   |   |--- base_image_age_days <= 1719.50
|   |   |   |   |   |--- class: WARN
|   |   |   |   |--- base_image_age_days > 1719.50
|   |   |   |   |   |--- class: BLOCK
|   |   |--- critical_cve_count > 49.00
|   |   |   |--- class: BLOCK
|--- top25_cwe_count > 143.00
|   |--- cvss_ge_7_count <= 133.00
|   |   |--- class: BLOCK
|   |--- cvss_ge_7_count > 133.00
|   |   |--- class: BLOCK
```

### Tree Observations

**Root split shifted to `top25_cwe_count`.** With more diverse examples, the tree found that the count of vulnerabilities matching MITRE Top 25 weakness classes is a stronger discriminator than raw image age. This is a more semantically correct root split — it directly measures known exploitable weakness coverage rather than inferring risk from temporal proximity to release.

**`base_image_age_days` persists as a secondary feature** and still drives several branches. The ALLOW/WARN boundary in the moderate-severity zone (high_cve ≤ 31.5, top25 ≤ 143) remains age-gated: images under 368 days skew ALLOW, older images skew WARN. The model has reduced its dependence on age but not eliminated it.

**The BLOCK boundary is now clean.** `top25_cwe_count > 143` → BLOCK unconditionally. `critical_cve_count > 49` → BLOCK. These are high-magnitude thresholds that correspond to the extreme vulnerability profiles in the `known-vuln` bucket (intentionally compromised images). No ambiguity at the high end of the risk spectrum.

---

## Known Limitations and What Changed Next

**`base_image_age_days` is still present.** Despite the root split improving, age still gates several branches in the middle of the tree. The non-determinism problem from v0.0.1 persists. Images near the 368-day boundary can flip ALLOW→WARN across scans. See `analysis/dataset-scale-up-analysis.md` for extended analysis.

**Threshold labels still map to bucket identity.** The high-qual bucket produced ~96 ALLOW labels not because those images have clean vulnerability profiles, but because the threshold constants were calibrated against bucket identity. This circular reference inflates apparent ALLOW quality.

**No escalation policy.** Low-confidence WARN predictions are still not escalated.

**→ v0.0.3** removes `base_image_age_days` completely and adjusts class weights.
**→ v0.0.4** raises WARN thresholds and introduces the confidence-based escalation policy.
