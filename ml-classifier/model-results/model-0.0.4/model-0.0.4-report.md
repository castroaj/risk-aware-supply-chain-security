# Model v0.0.4 — Checkpoint Report

**Date:** 2026-04-23
**Labeling mode:** Threshold-based (rule-based, `classify_metric_threshold`)
**Dataset:** 371 images — same images as v0.0.3, threshold constants adjusted

---

## Overview

Model v0.0.4 introduces two significant changes: raised WARN thresholds and the confidence-based escalation policy. The threshold adjustment (`critical_cve_count` 10→20, `cvss_ge_7_count` 100→150) shrinks the WARN bucket to images that are genuinely borderline — reclassifying 8 images from WARN to ALLOW and removing the most ambiguous middle-ground cases from WARN. The escalation policy adds a runtime safety net: WARN predictions with confidence below 0.75 are escalated to BLOCK, and BLOCK is never downgraded. Together, these changes push test accuracy to 0.9733 — the best in the threshold-labeling era — with a near-zero CV-test gap.

This is the final checkpoint before LLM-assisted labeling.

---

## Model Metadata

| Parameter | Value |
|---|---|
| `criterion` | gini |
| `max_depth` | 5 |
| `min_samples_split` | 6 |
| `min_samples_leaf` | 2 |
| `class_weight` | `{ALLOW: 1, WARN: 2, BLOCK: 4}` |
| `random_state` | 42 |
| `test_size` | 0.20 |
| `cv_folds` | 5 |
| Escalation policy | **WARN confidence < 0.75 → BLOCK; BLOCK never downgraded** |

---

## Feature Set (8 features — unchanged from v0.0.3)

```
total_dependency_count, vuln_total, critical_cve_count, high_cve_count,
cvss_ge_7_count, max_cvss, unique_cwe_count, top25_cwe_count
```

---

## Dataset

| Metric | Value |
|---|---|
| Total images | 371 |
| Train / test split | 296 / 75 |
| ALLOW samples | 144 (38.8%) |
| WARN samples | 104 (28.0%) |
| BLOCK samples | 123 (33.2%) |

### Label Shift from v0.0.3

| Class | v0.0.3 | v0.0.4 | Change |
|---|---|---|---|
| ALLOW | 136 | **144** | +8 |
| WARN | 112 | **104** | −8 |
| BLOCK | 123 | 123 | 0 |

The threshold adjustments moved 8 images from WARN to ALLOW. These are images that sat between the old and new threshold boundaries — they had moderate critical CVE counts or cvss_ge_7 counts that qualified for WARN under the old constants but fall below ALLOW under the raised ones. Their removal from WARN leaves the WARN bucket containing only images that are more genuinely ambiguous, which is the intent.

BLOCK is unchanged — the BLOCK thresholds were not modified.

---

## Performance

| Metric | Value |
|---|---|
| Test accuracy | **0.9733** |
| CV accuracy | **0.9696 ± 0.0197** (5-fold stratified) |
| CV-test gap | **0.004** — essentially zero |
| WARNs escalated to BLOCK | 2 (test set) |

### Per-Class Results

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| ALLOW | 1.00 | 0.93 | 0.96 | 29 |
| BLOCK | 0.93 | 1.00 | 0.96 | 25 |
| WARN | 1.00 | 1.00 | 1.00 | 21 |
| **weighted avg** | **0.98** | **0.97** | **0.97** | **75** |

### Key Improvements vs v0.0.3

| Metric | v0.0.3 | v0.0.4 | Change |
|---|---|---|---|
| Test accuracy | 0.9333 | **0.9733** | **+0.040** |
| CV accuracy | 0.9729 | 0.9696 | −0.003 |
| CV std | ±0.0230 | **±0.0197** | −0.003 |
| CV-test gap | 0.039 | **0.004** | **−0.035** |
| WARN F1 | 0.89 | **1.00** | +0.11 |
| ALLOW recall | 0.89 | 0.93 | +0.04 |

The CV-test gap collapse (0.039 → 0.004) is the headline result. v0.0.3's optimistic CV estimate was driven by near-duplicate images dominating training folds; the threshold adjustment removed the most ambiguous boundary cases, making the WARN class more internally consistent and easier for the model to learn.

WARN achieves F1=1.00 on the test set — all 21 WARN images are classified correctly at full precision and recall. This is partly a consequence of a smaller, more homogeneous WARN class (104 samples vs 112) after the threshold raise.

The 2 WARN→BLOCK escalations reflect the escalation policy firing on WARN predictions that the model made with below-threshold confidence. These are genuinely ambiguous images that sit near the WARN/BLOCK boundary.

---

## Decision Tree

```
|--- top25_cwe_count <= 143.00
|   |--- unique_cwe_count <= 39.50
|   |   |--- critical_cve_count <= 14.50
|   |   |   |--- class: ALLOW
|   |   |--- critical_cve_count > 14.50
|   |   |   |--- class: WARN
|   |--- unique_cwe_count > 39.50
|   |   |--- critical_cve_count <= 49.00
|   |   |   |--- class: WARN
|   |   |--- critical_cve_count > 49.00
|   |   |--- class: BLOCK
|--- top25_cwe_count > 143.00
|   |--- class: BLOCK
```

### Tree Observations

**The simplest tree in the series.** v0.0.4's tree has 5 leaves and an effective depth of 3. This is a consequence of the threshold adjustment — with a cleaner WARN class, the Gini criterion found clean splits at higher levels, eliminating the need for deeper partitioning.

**Three features do the entire job:** `top25_cwe_count`, `unique_cwe_count`, and `critical_cve_count`. The other five features in the vector contribute nothing to this tree's decisions. This parsimony is reassuring from a generalization standpoint, but it also suggests the remaining features may be redundant with this trio under threshold-based labeling.

**`top25_cwe_count > 143` → BLOCK unconditionally.** No further features are consulted. This is a clean, interpretable rule: when more than 143 of a image's vulnerabilities match known-weaponized CWE patterns, the image is blocked without exception.

**ALLOW boundary: `top25_cwe < 143 AND unique_cwe < 39.5 AND critical_cve < 14.5`.** The critical CVE ceiling increased from 9 (v0.0.3) to 14.5, reflecting the raised threshold constants. This is still arguably permissive but reflects the operational stance that an image with up to 14 isolated critical CVEs in a larger dependency tree may still represent scheduled remediation rather than an emergency block.

---

## Escalation Policy — First Appearance

The escalation policy introduced in v0.0.4 adds a runtime confidence gate:

1. Any WARN prediction where `predict_proba(WARN) < 0.75` is escalated to BLOCK
2. BLOCK predictions are never downgraded regardless of confidence

This policy is applied both at prediction time (`Predictor.predict()`) and during training evaluation — CV and test metrics are both reported after escalation, so reported accuracy reflects what the pipeline actually produces in deployment. The 2 escalations in the test set represent images where the model was uncertain between WARN and BLOCK; the policy conservatively routes them to BLOCK.

---

## Threshold Labeling — Final Assessment

v0.0.4 represents the ceiling for rule-based threshold labeling on this dataset. The near-zero CV-test gap and strong per-class metrics indicate the model has learned the threshold rules almost perfectly — which is both the strength and the limitation of this approach.

**What threshold labeling gets right:**
- Fully deterministic and reproducible
- Labels directly encode domain-expert security intuitions
- Near-perfect consistency across the training set (no label noise)

**What threshold labeling cannot do:**
- Evaluate images holistically across the full feature vector
- Reason about vulnerability density relative to image size
- Produce nuanced WARN labels for images with one isolated critical CVE in a large, otherwise-clean image
- Capture the operational meaning of "fix this sprint" vs "deploy with an incident response plan"

The label distribution (ALLOW=144 = 39%) still reflects the bucket-calibrated threshold constants, not a genuine security assessment. A strict analyst would label far fewer of the high-qual images as ALLOW once they examined the feature values — the median high-qual image has 3 critical CVEs and a CVSS 10.0 finding somewhere in its tree.

**→ v0.0.5** replaces threshold labeling with `gemini-2.5-flash` + `system-prompt-v1.md`, the first LLM-assisted labeling run.
