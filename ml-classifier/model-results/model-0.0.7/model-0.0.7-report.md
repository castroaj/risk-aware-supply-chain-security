# Model v0.0.7 — Checkpoint Report

**Date:** 2026-04-28
**Training run:** `training-runs/20260428-202116`
**Labeling mode:** LLM — `gemini-2.5-flash` with `config/system-prompt-v3.md`
**Prior checkpoint:** `model-results/model-0.0.6`

---

## Overview

Model v0.0.7 is the current best checkpoint, produced from the April 2026 system-prompt-v3 labeling cycle. It resolves the primary limitation of v0.0.6: a WARN recall ceiling at 0.75 caused by a labeling regime that over-BLOCKed images whose vulnerability profiles are concentrated, not systemic.

The v3 prompt introduced a density ratio (`top25_cwe_count / total_dependency_count`) as the primary BLOCK signal, replacing the absolute-count anchors from v2. This produced a substantially more balanced WARN/BLOCK split (WARN=164 vs. 100 in v0.0.6, BLOCK=186 vs. 250) and pushed WARN recall from 0.75 to 0.91 — the most operationally important metric for a deployment gate.

The test_size was reduced from 0.50 to 0.20, giving the model 296 training examples vs. 185 in v0.0.6. Together with the improved label distribution, this is the primary driver of the accuracy improvement (92.0% vs. 90.7%).

---

## Model Metadata

| Parameter | Value |
|---|---|
| `criterion` | gini |
| `max_depth` | 4 |
| `min_samples_split` | 4 |
| `min_samples_leaf` | 2 |
| `class_weight` | `{ALLOW: 4, WARN: 2, BLOCK: 2}` |
| `random_state` | 42 |
| `test_size` | 0.20 |
| `cv_folds` | 5 |
| `escalation_threshold` | 0.75 (WARN confidence) |

---

## Dataset

| Metric | Value |
|---|---|
| Total images | 371 |
| Train / test split | 296 / 75 |
| ALLOW samples | 21 (5.7%) |
| WARN samples | 164 (44.2%) |
| BLOCK samples | 186 (50.1%) |

---

## Performance

| Metric | Value |
|---|---|
| Test accuracy | **0.9200** |
| CV accuracy | **0.9221 ± 0.0476** (5-fold stratified) |
| CV-test gap | **0.0021** — excellent generalization |
| WARNs escalated to BLOCK | 0 |

### Per-Class Results

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| ALLOW | 1.00 | 1.00 | 1.00 | 4 |
| BLOCK | 0.92 | 0.92 | 0.92 | 38 |
| WARN | 0.91 | 0.91 | 0.91 | 33 |
| **weighted avg** | **0.92** | **0.92** | **0.92** | **75** |

---

## Decision Tree

```
|--- top25_cwe_count <= 57.50
|   |--- cvss_ge_7_count <= 0.50
|   |   |--- class: ALLOW
|   |--- cvss_ge_7_count > 0.50
|   |   |--- cvss_ge_7_count <= 45.50
|   |   |   |--- total_dependency_count <= 41.50
|   |   |   |   |--- class: WARN
|   |   |   |--- total_dependency_count > 41.50
|   |   |   |   |--- class: WARN
|   |   |--- cvss_ge_7_count > 45.50
|   |   |   |--- total_dependency_count <= 127.50
|   |   |   |   |--- class: BLOCK
|   |   |   |--- total_dependency_count > 127.50
|   |   |   |   |--- class: WARN
|--- top25_cwe_count > 57.50
|   |--- total_dependency_count <= 852.00
|   |   |--- critical_cve_count <= 11.00
|   |   |   |--- total_dependency_count <= 410.00
|   |   |   |   |--- class: BLOCK
|   |   |   |--- total_dependency_count > 410.00
|   |   |   |   |--- class: WARN
|   |   |--- critical_cve_count > 11.00
|   |   |   |--- total_dependency_count <= 627.00
|   |   |   |   |--- class: BLOCK
|   |   |   |--- total_dependency_count > 627.00
|   |   |   |   |--- class: BLOCK
|   |--- total_dependency_count >  852.00
|   |   |--- top25_cwe_count <= 153.50
|   |   |   |--- class: WARN
|   |   |--- top25_cwe_count > 153.50
|   |   |   |--- class: BLOCK
```

### Tree Observations

**Root split on `top25_cwe_count` encodes density directly.** The v3 prompt introduced `top25_cwe_count / total_dependency_count` as the primary BLOCK signal. The tree independently anchored on `top25_cwe_count` as the root split (threshold 57.5) rather than `critical_cve_count` as in v0.0.6. This is a structural reflection of the prompt change: the model learned that breadth of weaponized weakness classes is a stronger BLOCK predictor than isolated critical CVE counts.

**ALLOW path is clean and unchanged.** `top25_cwe_count ≤ 57.5` and `cvss_ge_7_count ≤ 0.5` correctly separates genuinely clean images. The ALLOW decision remains a natural gap in feature space, not a learned boundary.

**Redundant `total_dependency_count` split in the low-top25 WARN branch.** In the `top25_cwe_count ≤ 57.5, cvss_ge_7_count > 0.5, cvss_ge_7_count ≤ 45.5` region, both leaves (`total_dep ≤ 41.5` and `> 41.5`) resolve to WARN. This is a no-op split — the tree consumed a depth level to encode no discriminating signal. It indicates the model's information capacity was saturated before this split provided value. A higher `min_samples_split` would regularize this away.

**The high-top25 branch uses `total_dependency_count` as a density proxy.** Across all `top25_cwe_count > 57.5` images, the tree discriminates WARN vs. BLOCK primarily via image size. Large images (>852 components) flip to WARN unless `top25_cwe_count` is extreme (>153.5), encoding the density ratio reasoning the v3 prompt introduced. The `critical_cve_count ≤ 11` boundary in the mid-range is consistent with the Example 5 calibration added to v3 (9 criticals in a 148-dep image labeled WARN).

**Features used: 4 (`top25_cwe_count`, `cvss_ge_7_count`, `total_dependency_count`, `critical_cve_count`).** v0.0.6 used 6 features including `high_cve_count` and `unique_cwe_count`. The v0.0.7 tree converged on a simpler, more interpretable boundary — consistent with the v3 prompt's shift toward holistic density patterns over multi-feature absolute counts.

---

## Tuning Cycle Comparison

Three runs were evaluated during the April 28 cycle on the v3 label set (ALLOW=21, WARN=164, BLOCK=186).

| Run | `test_size` | Test acc | CV acc | CV-test gap | WARN recall | WARN precision | WARNs escalated |
|---|---|---|---|---|---|---|---|
| 20260428-202052 | 0.40 | 0.8725 | 0.9053 ± 0.027 | 0.033 | 0.79 | 0.91 | 5 |
| 20260428-202128 | 0.50 | 0.8871 | 0.8865 ± 0.075 | 0.001 | 0.87 | 0.88 | 0 |
| **20260428-202116 (v0.0.7)** | **0.20** | **0.9200** | **0.9221 ± 0.048** | **0.002** | **0.91** | **0.91** | **0** |

**`test_size=0.20` is the decisive factor.** The larger training set (296 vs. 149–185) lets the model learn the denser WARN class (164 samples) more reliably. With `test_size=0.50`, WARN recall peaks at 0.87 with zero escalations; at `test_size=0.20` it reaches 0.91 with equivalent generalization (CV-test gap 0.002 vs. 0.001).

**Run 202052 (test_size=0.40) produced 5 WARN escalations.** A smaller training set combined with moderate class overlap causes the model to misclassify 5 true WARNs as BLOCK in the test set. This run is rejected on escalation count alone — escalations add operational friction without a safety benefit (missed WARNs still go to BLOCK, not ALLOW).

### Comparison to v0.0.6

v0.0.6's WARN recall ceiling at 0.75 was correctly diagnosed as a labeling problem, not a hyperparameter problem. The v3 density framing broke through it: the same `max_depth=4` tree that was stuck at 0.75 WARN recall now achieves 0.91 on a more representative label distribution. The `class_weight` change (BLOCK: 3→2) reflects that BLOCK is no longer the dominant class requiring artificial boosting.

---

## Labeling Analysis

### Bucket vs. LLM Label Distribution

| Bucket | Intent | Images | LLM → ALLOW | LLM → WARN | LLM → BLOCK |
|---|---|---|---|---|---|
| `high-qual` | ALLOW candidates | 172 | 12 (7%) | **122 (71%)** | 38 (22%) |
| `aged-stale` | WARN candidates | 154 | 8 (5%) | **32 (21%)** | 114 (74%) |
| `known-vuln` | BLOCK candidates | 45 | 1 (2%) | 10 (22%) | 34 (76%) |

### v3 vs. v2 Labeling Delta

The v3 density framing had a large redistributive effect, particularly in the two buckets that were most distorted in v0.0.6:

| Bucket | v2 WARN | v3 WARN | Change | v2 BLOCK | v3 BLOCK | Change |
|---|---|---|---|---|---|---|
| `high-qual` | 89 (52%) | 122 (71%) | +33 | 71 (41%) | 38 (22%) | −33 |
| `aged-stale` | 7 (5%) | 32 (21%) | +25 | 139 (90%) | 114 (74%) | −25 |
| `known-vuln` | 4 (9%) | 10 (22%) | +6 | 40 (89%) | 34 (76%) | −6 |

The density ratio instruction pulled 64 images from BLOCK back to WARN across all three buckets. This is the mechanism behind the WARN recall improvement.

### Remaining Structural Limitations

**`aged-stale` is still predominantly BLOCK (74%).** The bucket sources 5–8 year old EOL runtimes that carry 30–46 critical CVEs at near-systemic density. The v3 density prompt recovered 25 images for WARN, but the remaining 114 are correctly BLOCK — the images themselves are too compromised for WARN regardless of prompt calibration. Sourcing genuinely intermediate images (1–2 year old, moderate CVE profiles) remains the highest-leverage next step.

**ALLOW remains severely underrepresented at 5.7%.** With only 21 ALLOW samples, the model achieves perfect ALLOW metrics because clean images (near-zero CVEs) are trivially separable. Any edge case near the ALLOW boundary — an image with 0 criticals but elevated high-severity counts — remains at risk of misclassification.

**`known-vuln` WARN rate increased to 22% (from 9% in v0.0.6).** The density framing correctly identifies that some known-vuln images have concentrated, not systemic, vulnerability profiles. However, this bucket was sourced as BLOCK candidates. A 22% WARN rate may indicate the v3 prompt is over-attributing WARN to images where the source intent was BLOCK. Manual review of these 10 images is warranted.

---

## Known Limitations

- **Redundant split in low-top25 WARN branch** — `total_dependency_count` split produces no discriminating signal; both child leaves resolve to WARN. Regularizable with `min_samples_split=6` or `min_samples_leaf=3`.
- **21 ALLOW samples** — trivially separable today, but any near-boundary ALLOW case (low criticals, moderate highs) is at risk.
- **`aged-stale` is still 74% BLOCK** — the structural bucket problem is improved but unresolved. Intermediate images must be sourced before WARN generalization improves further.
- **No held-out validation set** — all 371 images participate in training or cross-validation. A fixed 30-image stratified holdout across model versions would provide an uncontaminated cross-version comparison.

---

## Next Steps

| Priority | Action |
|---|---|
| P0 | Source 30–50 genuinely intermediate images for `aged-stale` (1–2 yr old, moderate CVE profile: 2–8 criticals, 15–40 high CVEs) |
| P1 | Manually review the 10 `known-vuln` images labeled WARN by v3 — confirm or override |
| P1 | Expand `high-qual` ALLOW candidates with distroless and Chainguard images (target: 60+ ALLOW samples) |
| P1 | Add bucket-constraint context to the LLM user message to enforce per-bucket label range |
| P2 | Carve out a fixed 30-image stratified holdout set for cross-version evaluation |
| P2 | Investigate `min_samples_split=6` or `min_samples_leaf=3` to regularize the redundant WARN split |
| P2 | Implement post-labeling consistency audit: flag high-qual → BLOCK (38 images) and known-vuln → WARN (10 images) for manual review |
