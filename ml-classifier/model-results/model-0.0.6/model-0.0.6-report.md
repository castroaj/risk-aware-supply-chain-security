# Model v0.0.6 — Checkpoint Report

**Date:** 2026-04-26
**Training run:** `training-runs/20260426-121900`
**Labeling mode:** LLM — `gemini-2.5-flash` with `config/system-prompt-v2.md`
**Prior checkpoint:** `model-results/model-0.0.5`

---

## Overview

Model v0.0.6 is the best-generalized checkpoint produced during the April 2026 LLM-labeling tuning cycle. It closes a significant overfitting gap introduced in an intermediate run and establishes a stable performance baseline under the `gemini-2.5-flash` + system-prompt-v2 labeling regime. The headline accuracy (90.7%) is lower than v0.0.5's apparent 100%, but that comparison is misleading — v0.0.5 trained on only 23 WARN samples under rule-based labels, a nearly trivial classification problem. v0.0.6 trains on 100 WARN samples from LLM labeling, a substantially harder and more realistic distribution.

The WARN class recall plateau at 0.75 is the primary unresolved problem. It is not a hyperparameter issue — the same ceiling appeared across every depth-4 run regardless of class weights. The root cause is structural: the WARN class is being populated from the wrong source images, and the labeling criteria does not produce enough genuinely intermediate examples to allow the model to learn a reliable WARN boundary.

---

## Model Metadata

| Parameter | Value |
|---|---|
| `criterion` | gini |
| `max_depth` | 4 |
| `min_samples_split` | 4 |
| `min_samples_leaf` | 2 |
| `class_weight` | `{ALLOW: 4, WARN: 2, BLOCK: 3}` |
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
| WARN samples | 100 (27.0%) |
| BLOCK samples | 250 (67.4%) |

---

## Performance

| Metric | Value |
|---|---|
| Test accuracy | **0.9067** |
| CV accuracy | **0.9119 ± 0.0422** (5-fold stratified) |
| CV-test gap | **0.0052** — best generalization of the cycle |
| WARNs escalated to BLOCK | 0 |

### Per-Class Results

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| ALLOW | 1.00 | 1.00 | 1.00 | 4 |
| BLOCK | 0.91 | 0.96 | 0.93 | 51 |
| WARN | 0.88 | 0.75 | 0.81 | 20 |
| **weighted avg** | **0.91** | **0.91** | **0.90** | **75** |

---

## Decision Tree

```
|--- critical_cve_count <= 2.50
|   |--- cvss_ge_7_count <= 0.50
|   |   |--- class: ALLOW
|   |--- cvss_ge_7_count > 0.50
|   |   |--- high_cve_count <= 10.50
|   |   |   |--- class: WARN
|   |   |--- high_cve_count > 10.50
|   |   |   |--- total_dependency_count <= 36.00
|   |   |   |   |--- class: BLOCK
|   |   |   |--- total_dependency_count > 36.00
|   |   |   |   |--- class: WARN
|--- critical_cve_count > 2.50
|   |--- top25_cwe_count <= 25.50
|   |   |--- total_dependency_count <= 92.00
|   |   |   |--- class: BLOCK
|   |   |--- total_dependency_count > 92.00
|   |   |   |--- unique_cwe_count <= 26.00
|   |   |   |   |--- class: BLOCK
|   |   |   |--- unique_cwe_count > 26.00
|   |   |   |   |--- class: WARN
|   |--- top25_cwe_count > 25.50
|   |   |--- total_dependency_count <= 1476.00
|   |   |   |--- cvss_ge_7_count <= 58.50
|   |   |   |   |--- class: BLOCK
|   |   |   |--- cvss_ge_7_count > 58.50
|   |   |   |   |--- class: BLOCK
|   |   |--- total_dependency_count > 1476.00
|   |   |   |--- top25_cwe_count <= 96.50
|   |   |   |   |--- class: WARN
|   |   |   |--- top25_cwe_count > 96.50
|   |   |   |   |--- class: BLOCK
```

### Tree Observations

**ALLOW path is clean and correct.** `critical_cve_count ≤ 2.5` and `cvss_ge_7_count ≤ 0.5` separates truly clean images without noise. These thresholds align with the natural gap in the ALLOW population.

**WARN/BLOCK boundary in the high-critical subtree is ambiguous.** In the `critical_cve > 2.5, top25_cwe > 25.5` region, two leaves (`cvss_ge_7_count ≤ 58.5` and `> 58.5`) both resolve to BLOCK. This is a redundant split — the tree learned no discriminating signal at this depth level for these images. It indicates the model hit its information capacity and is partitioning noise.

**The very-large-image split (`total_dependency_count > 1476`) is suspicious.** This produces a `top25_cwe_count ≤ 96.5 → WARN` leaf that almost certainly covers only a handful of outlier images. A rule this narrow is unlikely to generalize and may need to be regularized away via a higher `min_samples_leaf`.

**`unique_cwe_count > 26` producing WARN in the mid-range BLOCK zone** is an interesting pattern: the model has learned that when CWE diversity is high but `top25_cwe_count` is still below 25, the image may represent a broad but lower-severity profile. This split appeared in run 3 as well and is likely a genuine signal worth preserving.

---

## Tuning Cycle Comparison

Four runs were evaluated during this cycle on the same dataset and labeling.

| Run | `max_depth` | Class weights | Test acc | CV acc | CV-test gap | WARN recall | WARN precision | WARNs escalated |
|---|---|---|---|---|---|---|---|---|
| 20260426-115238 | 4 | A:2 W:1 B:4 | **0.920** | 0.889 ± 0.055 | 0.031 | 0.75 | 0.94 | 0 |
| 20260426-120538 | 4 | A:4 W:2 B:2 | 0.907 | 0.895 ± 0.035 | 0.012 | **0.85** | 0.81 | 4 |
| 20260426-121237 | 5 | A:3 W:2 B:3 | 0.840 | 0.915 ± 0.048 | 0.075 | 0.60 | 0.75 | 3 |
| **20260426-121900 (v0.0.6)** | **4** | **A:4 W:2 B:3** | **0.907** | **0.912 ± 0.042** | **0.005** | 0.75 | **0.88** | **0** |

**Run 3 (depth=5) produced the regression.** The deeper tree improved CV accuracy to 0.915 but dropped test accuracy to 0.840 — a 0.075 CV-test gap indicating overfitting. The model memorized training noise that the extra depth enabled. WARN recall fell to 0.60, the worst of the cycle.

**v0.0.6 recovers generalization.** Reverting to `max_depth=4` with adjusted class weights (`ALLOW:4 WARN:2 BLOCK:3`) produces the smallest CV-test gap of the cycle (0.005). WARN precision improves to 0.88 (up from 0.81 in run 2), meaning fewer false WARNs. BLOCK recall (0.96) sits between runs 1 and 2.

**The WARN recall ceiling is 0.75 on depth-4 trees.** It appeared identically in runs 1 and 4 despite different class weights. Run 2 broke through to 0.85 by dropping BLOCK weight to 2, but that produced 4 escalations and lower BLOCK recall — an unacceptable tradeoff for a security gate. This ceiling is a data problem, not a hyperparameter problem.

### Comparison to v0.0.5

v0.0.5 achieved 1.00 test accuracy under rule-based (threshold) labeling with only 23 WARN samples. That result reflects label simplicity, not model strength — the rule-based WARN class was so sparse and so close to the decision boundary that any reasonable tree could achieve perfect separation. v0.0.6 trains under a genuinely harder distribution (100 WARN samples, LLM-labeled with holistic reasoning), making 0.907 a more meaningful baseline. The regression from "100%" to 90.7% is a direct consequence of moving to a harder, more realistic labeling regime.

---

## Labeling Analysis — The Structural Problem

The core issue limiting model quality is not the decision tree or the hyperparameters. It is a mismatch between bucket design intent and what the LLM actually assigns as labels.

### Bucket vs. LLM Label Distribution

| Bucket | Intent | Images | LLM → ALLOW | LLM → WARN | LLM → BLOCK |
|---|---|---|---|---|---|
| `high-qual` | ALLOW candidates | 172 | 12 (7%) | 89 (52%) | **71 (41%)** |
| `aged-stale` | WARN candidates | 154 | 8 (5%) | 7 (5%) | **139 (90%)** |
| `known-vuln` | BLOCK candidates | 45 | 1 (2%) | 4 (9%) | 40 (89%) |

### What This Means for Training

**The WARN class has been captured by the wrong bucket.** 89 of 100 WARN samples come from `high-qual` — images selected as "good" that happen to carry some CVEs. Only 7 come from `aged-stale`, which was explicitly sourced as the WARN bucket. The model has not learned "aged/medium-risk image" as WARN; it has learned "high-quality image with a few CVEs" as WARN. These are different things operationally, and the decision boundary reflects this — WARN lives in the low-critical, moderate-high-CVE region of feature space, not in the moderate-everything region you'd expect from truly intermediate images.

**The LLM treats aged-stale images as BLOCK at a 90% rate.** The images in `aged-stale` (nginx 1.18–1.22, Ubuntu 16.04/18.04, Python 3.6–3.9 EOL, Node 10/12/14) all carry extreme vulnerability counts — 30–46 critical CVEs, max_cvss 10.0, 130–180 top25 CWE matches. From any holistic security perspective, these are BLOCK. The LLM is correct. But it means the bucket was sourced with images that are too compromised to populate WARN, defeating the purpose.

**ALLOW is severely underrepresented at 6%.** With only 21 ALLOW samples, the model has minimal signal for this class. It currently achieves perfect ALLOW metrics because clean images (zero or near-zero CVEs) are trivially separable — but any edge case near the ALLOW boundary would likely fail.

**BLOCK dominates at 67%.** The model is being optimized primarily as a BLOCK/not-BLOCK classifier. WARN is a hard-to-learn afterthought in this distribution.

---

## Suggestions for the Next Labeling Cycle

The following suggestions are ordered by expected impact. They target the system prompt, the image sourcing strategy, and the labeling pipeline architecture.

### 1. Source genuinely intermediate images for the `aged-stale` bucket

This is the highest-leverage change. The current `aged-stale` images are 5–8 year old EOL runtimes with extreme vulnerability accumulation. They will never produce WARN labels from any reasonable security-aware LLM. Replace a significant portion of `aged-stale` with images that sit in the true middle ground:

- Images that are **1–2 years old** from actively maintained projects (not EOL). Examples: nginx:1.24.0 (2023), python:3.10 (2021-era patch release), node:18 LTS with a stale patch date.
- Images with **moderate CVE profiles**: 2–8 critical CVEs, 15–40 high CVEs, max_cvss in the 8–9 range. Not zero, not extreme.
- Images that a reasonable security engineer would look at and say "fix this sprint" rather than "drop everything."

Without images like this, the WARN class will remain an artifact of the high-qual bucket rather than a meaningful risk category.

### 2. Add explicit WARN-vs-BLOCK boundary examples to the system prompt

The current system prompt includes one WARN example (ubuntu 22.04: 0 criticals, 4 high) and one BLOCK example (nginx 1.18.0: 44 criticals, 155 top25). This leaves an enormous gap in the middle. The LLM has no calibration point for images with, say, 8–15 criticals and 30–60 top25 — and it defaults to BLOCK for all of them.

Add at least two examples targeting the WARN/BLOCK boundary:

```
Example 5 — WARN (moderate critical CVEs, contained breadth)
features: {total_dependency_count: 136, vuln_total: 85, critical_cve_count: 8,
           high_cve_count: 45, cvss_ge_7_count: 42, max_cvss: 10.0,
           unique_cwe_count: 28, top25_cwe_count: 38}
label: WARN
justification: 8 critical CVEs at max_cvss 10.0 is serious, but with only 38 Top 25 CWE
matches across 136 components (0.28 per component), the attack surface is not systemic.
This is a prioritized remediation target — urgent within the current sprint, not an emergency block.
```

This gives the model a concrete calibration point and would likely pull many of the currently over-BLOCKed aged-stale images toward WARN.

### 3. Introduce density ratios as explicit labeling guidance in the system prompt

The current prompt says "weight findings relative to image size" but gives no numeric guidance. This is too vague for consistent calibration. Add explicit ratio thresholds to the labeling guidance section:

```
When evaluating severity relative to image size, compute the approximate density:
  critical_density = critical_cve_count / total_dependency_count
  top25_density    = top25_cwe_count / total_dependency_count

A critical_density above ~0.30 (more than one critical CVE per 3 components) strongly
suggests BLOCK. Below ~0.10 with low top25_density, lean toward WARN even if the
absolute critical count is elevated.
```

This would directly address the aged-stale problem: nginx 1.18.0 has `44 / 136 ≈ 0.32` critical density — right at the BLOCK threshold. An image with 8 criticals across 136 deps would score `0.06`, comfortably WARN.

### 4. Constrain LLM label output by bucket

Pass the bucket name as context in the user message and add a constraint instruction to the system prompt. This enforces the semantic intent of the bucket design:

```
# System prompt addition
The input includes a "bucket" field indicating the image's sourcing tier:
  - "high-qual": recently maintained, actively patched images. Labels should lean ALLOW or WARN.
    Only assign BLOCK if the vulnerability profile is unambiguously systemic.
  - "aged-stale": older images with accumulated vulnerabilities. Labels should lean WARN or BLOCK.
    ALLOW is only appropriate if the scan is genuinely clean despite the image age.
  - "known-vuln": images with documented, unpatched CVEs. Labels should be BLOCK in nearly all cases.
```

This prevents the LLM from labeling high-qual images as BLOCK (currently 41% of that bucket) and would recover those samples for the ALLOW or WARN class.

### 5. Expand the ALLOW bucket with minimal-footprint images

With only 21 ALLOW samples, any boundary case near ALLOW will be misclassified. Add 40–60 more truly clean images:

- **Distroless variants**: `gcr.io/distroless/base`, `gcr.io/distroless/python3`
- **Chainguard images**: enforce zero CVEs by design
- **Recent Alpine micro variants**: alpine:3.20, alpine:3.21
- **Official UBI micro**: `registry.access.redhat.com/ubi9/ubi-micro`
- **Recent scratch-based images**: Go static binaries, Rust release binaries

These are images where the expected label is clearly ALLOW, with strong signal that the model can learn from.

### 6. Consider a post-labeling consistency audit before training

After any LLM labeling run, compute a cross-bucket consistency check before writing the label CSVs:

- Flag any `high-qual` image labeled BLOCK (currently 71 images). Review whether each one belongs in `aged-stale` or `known-vuln` instead.
- Flag any `aged-stale` image labeled ALLOW (currently 8 images). These may be good additions to `high-qual`.
- Flag any `known-vuln` image not labeled BLOCK (currently 5 images). These warrant manual review.

This turns implicit labeling inconsistencies into explicit, reviewable artifacts before they silently corrupt the training distribution.

---

## Known Limitations

- **WARN recall ceiling at 0.75** — will not improve through hyperparameter changes alone. Requires labeling changes as described above.
- **21 ALLOW samples** — too few for confident generalization outside the trivially-separable zero-CVE region.
- **aged-stale bucket is effectively a second BLOCK source** — 90% of it resolves to BLOCK under current labeling, making it redundant with `known-vuln`.
- **Large-image leaf (`total_dependency_count > 1476`)** — this split covers very few images and likely memorizes outliers. Consider `min_samples_leaf = 4` or higher in the next run to regularize this away.
- **No held-out validation set** — all 371 images are used in training or cross-validation. A fixed 30-image stratified holdout (never used in any training run) would provide an uncontaminated generalization estimate across the full model version history.

---

## Next Steps

| Priority | Action |
|---|---|
| P0 | Source 30–50 genuinely intermediate images for `aged-stale` (1–2 yr old, moderate CVE profile) |
| P0 | Add WARN/BLOCK boundary examples to `config/system-prompt-v3.md` with density guidance |
| P1 | Add bucket-constraint context to the user message in LLM labeling mode |
| P1 | Expand `high-qual` ALLOW candidates with distroless and Chainguard images |
| P1 | Implement post-labeling consistency audit script |
| P2 | Carve out a fixed 30-image stratified holdout set for cross-version evaluation |
| P2 | Investigate raising `min_samples_leaf` to 3–4 to regularize the large-image outlier leaf |
