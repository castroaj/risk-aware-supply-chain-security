# Model v0.0.3 — Checkpoint Report

**Date:** 2026-04-23
**Labeling mode:** Threshold-based (rule-based, `classify_metric_threshold`)
**Dataset:** 371 images — same images as v0.0.2, re-labeled without `base_image_age_days`

---

## Overview

Model v0.0.3 removes `base_image_age_days` from the feature set — the most consequential architectural change across the v0.0.x series. This forces the tree to learn purely from vulnerability metrics and dependency structure, which is the correct basis for supply chain risk assessment. The relabeling that accompanies the feature removal also shifts the class distribution significantly: many images that were previously labeled WARN due to elevated age are now labeled ALLOW because their vulnerability profiles are genuinely clean. The result is the most balanced class distribution in the series (136/123/112), though this balance is itself a byproduct of how the threshold constants were calibrated.

Test accuracy drops to 0.9333 from v0.0.2's 0.9600, but CV accuracy rises to 0.9729. The divergence (0.039 gap) is a flag — the model is performing well on training folds but not as well on the held-out test set.

---

## Model Metadata

| Parameter | Value |
|---|---|
| `criterion` | gini |
| `max_depth` | 5 |
| `min_samples_split` | 6 |
| `min_samples_leaf  ` | 2 |
| `class_weight` | `{ALLOW: 1, WARN: 2, BLOCK: 4}` |
| `random_state` | 42 |
| `test_size` | 0.20 |
| `cv_folds` | 5 |
| Escalation policy | None |

---

## Feature Set (8 features — `base_image_age_days` removed)

```
total_dependency_count, vuln_total, critical_cve_count, high_cve_count,
cvss_ge_7_count, max_cvss, unique_cwe_count, top25_cwe_count
```

`base_image_age_days` was removed because:
1. It is computed from Docker Hub API metadata at scan time, introducing non-determinism (timeouts return 0, tags may be reassigned)
2. It encodes the data collection strategy (bucket identity) rather than vulnerability signal
3. It will not generalize to images outside the training distribution's age range
4. A secure image should be identifiable from its vulnerability profile alone

---

## Dataset

| Metric | Value |
|---|---|
| Total images | 371 |
| Train / test split | 296 / 75 |
| ALLOW samples | 136 (36.7%) |
| WARN samples | 112 (30.2%) |
| BLOCK samples | 123 (33.2%) |

### Label Shift from v0.0.2

| Class | v0.0.2 | v0.0.3 | Change |
|---|---|---|---|
| ALLOW | 96 | **136** | +40 |
| WARN | 151 | **112** | −39 |
| BLOCK | 124 | 123 | −1 |

Removing `base_image_age_days` from the feature pipeline also required removing it from the threshold classifier — which previously used image age as a WARN signal. Without age, images are labeled purely on vulnerability counts. The ~40 images that were WARN solely because they were older than the age threshold are now ALLOW, since their CVE profiles meet the ALLOW criteria. The near-perfect three-way balance (136/123/112) is an outcome of this relabeling, not a design target.

---

## Performance

| Metric | Value |
|---|---|
| Test accuracy | **0.9333** |
| CV accuracy | **0.9729 ± 0.0230** (5-fold stratified) |
| CV-test gap | **0.039** — highest in the series so far |

### Per-Class Results

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| ALLOW | 1.00 | 0.89 | 0.94 | 27 |
| BLOCK | 0.93 | 1.00 | 0.96 | 25 |
| WARN | 0.88 | 0.91 | 0.89 | 23 |
| **macro avg** | **0.93** | **0.93** | **0.93** | **75** |

### Notable Changes vs v0.0.2

ALLOW recall drops from 0.95 to 0.89 — approximately 3 images that should be ALLOW are predicted as WARN. This is likely due to relabeling: images near the ALLOW/WARN boundary that previously fell on the ALLOW side via age are now borderline on pure vulnerability metrics.

BLOCK recall holds at 1.00 for the second consecutive version — no BLOCK images are misclassified. WARN F1 is 0.89, weaker than v0.0.2's 0.95.

### CV-Test Gap

The 0.039 gap (0.9729 CV vs 0.9333 test) is the largest seen so far. The CV estimate is likely optimistic because the 296-image training set contains many images with near-identical profiles (multiple nginx versions, multiple Python EOL versions), which makes cross-validation folds artificially similar to each other. The harder boundary cases concentrate in the test set by chance under this random seed.

---

## Decision Tree

```
|--- top25_cwe_count <= 134.00
|   |--- unique_cwe_count <= 37.50
|   |   |--- critical_cve_count <= 9.00
|   |   |   |--- class: ALLOW
|   |   |--- critical_cve_count > 9.00
|   |   |   |--- class: WARN
|   |--- unique_cwe_count > 37.50
|   |   |--- critical_cve_count <= 49.00
|   |   |   |--- unique_cwe_count <= 39.50
|   |   |   |   |--- class: WARN
|   |   |   |--- unique_cwe_count > 39.50
|   |   |   |   |--- class: WARN
|   |   |--- critical_cve_count > 49.00
|   |   |   |--- class: BLOCK
|--- top25_cwe_count > 134.00
|   |--- high_cve_count <= 178.00
|   |   |--- class: BLOCK
|   |--- high_cve_count > 178.00
|   |   |--- class: BLOCK
```

### Tree Observations

**`base_image_age_days` is completely absent.** For the first time, every split in the tree is grounded in vulnerability data — `top25_cwe_count`, `unique_cwe_count`, and `critical_cve_count`. The tree is now expressing genuine risk logic.

**The tree is shallow and clean.** Removing the age feature eliminated several redundant branches. The effective depth is 3 in most paths, which improves interpretability and is appropriate for a dataset of this size.

**ALLOW is fully described by `top25_cwe < 134 AND unique_cwe < 37.5 AND critical_cve < 9`.** This is a reasonable combination — low CWE coverage, few unique weakness types, and fewer than 9 critical CVEs. The upper bound of 9 criticals for ALLOW may be too permissive (this is addressed in v0.0.4 by threshold adjustments).

**The WARN/BLOCK boundary is at `critical_cve_count = 49`** in the high-unique-CWE region. This is a very high bar for BLOCK within the `top25_cwe < 134` subtree — an image with 48 critical CVEs and high CWE diversity would still be predicted WARN. This threshold was inherited from the rule-based labeling constants.

**Two BLOCK leaves are redundant:** `high_cve ≤ 178` and `high_cve > 178` both resolve to BLOCK. This is the same artifact noted in v0.0.6 — the tree partitioned noise at the final depth level without finding a discriminating signal.

---

## Known Limitations and What Changed Next

**CV-test gap of 0.039 is concerning.** The model may be slightly overfitting to the correlated structure of the training set (many near-duplicate images across versions of the same base image).

**No escalation policy.** WARN predictions are not confidence-gated.

**WARN threshold in the ALLOW path is inherited from rule-based constants.** `critical_cve_count ≤ 9 → ALLOW` is the threshold constant's boundary encoded into the tree. When threshold constants change, the tree boundary will shift — this is the label drift problem.

**→ v0.0.4** raises WARN thresholds (critical_cve 10→20, cvss_ge_7 100→150) to reduce the WARN bucket to genuinely borderline images, and introduces the confidence-based escalation policy.
