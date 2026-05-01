# Model v0.0.5 — Checkpoint Report

**Date:** 2026-04-25
**Labeling mode:** LLM — `gemini-2.5-flash` with `config/system-prompt-v1.md` (first LLM run)
**Dataset:** 371 images — same images, relabeled by LLM

---

## Overview

Model v0.0.5 is the first checkpoint produced under LLM-assisted labeling. The shift from `classify_metric_threshold` to `gemini-2.5-flash` + `system-prompt-v1.md` is the most significant pipeline change in the series. LLM labeling is intended to produce holistic, human-reasoning-aligned labels rather than rigid threshold rules — allowing nuanced WARN assignments for images with isolated critical CVEs in large dependency trees, which the rule-based system could not express.

The resulting model reports 1.00 test accuracy and 0.9933 CV accuracy. These numbers are technically correct but reflect a near-trivial classification problem: the v1 system prompt produced an extreme BLOCK concentration (BLOCK=327, 88% of the dataset) that collapsed the decision boundary. The tree needs only two splits to classify the entire dataset. v0.0.5 is not a better model than v0.0.4 — it is a simpler model trained on a more poorly distributed label set.

The root cause is the v1 prompt itself. See `analysis/llm-labeling-evaluation-v1-vs-v2.md` for full analysis.

---

## Model Metadata

| Parameter | Value |
|---|---|
| `criterion` | gini |
| `max_depth` | 5 |
| `min_samples_split` | 6 |
| `min_samples_leaf` | 2 |
| `class_weight` | `{ALLOW: 1, WARN: 1, BLOCK: 2}` |
| `random_state` | 42 |
| `test_size` | 0.20 |
| `cv_folds` | 5 |
| Escalation policy | WARN confidence < 0.75 → BLOCK; BLOCK never downgraded |

---

## Feature Set (8 features — unchanged)

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
| ALLOW samples | 21 (5.7%) |
| WARN samples | 23 (6.2%) |
| BLOCK samples | **327 (88.1%)** |

### Label Shift from v0.0.4

| Class | v0.0.4 | v0.0.5 | Change |
|---|---|---|---|
| ALLOW | 144 | **21** | −123 |
| WARN | 104 | **23** | −81 |
| BLOCK | 123 | **327** | **+204** |

This is the most dramatic distribution shift in the series. 88% of the dataset is BLOCK. Both ALLOW and WARN are reduced to very small minority classes (21 and 23 samples respectively). The distribution is almost binary: BLOCK vs not-BLOCK.

### Per-Bucket LLM Label Distribution (v1 prompt)

| Bucket | Intent | ALLOW | WARN | BLOCK |
|---|---|---|---|---|
| `high-qual` (172 images) | ALLOW candidates | 28 (16%) | 18 (10%) | **127 (74%)** |
| `aged-stale` (154 images) | WARN candidates | 18 (12%) | **137 (89%)** | 0 (0%) |
| `known-vuln` (45 images) | BLOCK candidates | 1 (2%) | 0 (0%) | **45 (98%)** |

The v1 prompt produced two distinct anomalies:
1. **High-qual bucket**: 74% labeled BLOCK. The LLM correctly followed the v1 criterion ("one or more CRITICAL CVEs alongside systemic weakness breadth → BLOCK"), which fires on nearly every real-world production image with any critical CVE. The prompt was miscalibrated, not the model.
2. **Aged-stale bucket**: 89% labeled WARN with 0% BLOCK. Images with 44–97 critical CVEs at max_cvss 10.0 were labeled WARN. The justifications describe BLOCK-level findings but assign WARN. The most likely explanation is an earlier draft of the prompt was used, or the `bucket_label` column in the user message influenced the output.

---

## Performance

| Metric | Value |
|---|---|
| Test accuracy | **1.0000** |
| CV accuracy | **0.9933 ± 0.0082** (5-fold stratified) |
| CV-test gap | **0.007** |
| WARNs escalated to BLOCK | 0 |

### Per-Class Results

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| ALLOW | 1.00 | 1.00 | 1.00 | 4 |
| BLOCK | 1.00 | 1.00 | 1.00 | 66 |
| WARN | 1.00 | 1.00 | 1.00 | 5 |
| **accuracy** | | | **1.00** | **75** |

### Why 1.00 Accuracy Is Not a Good Result

The test set contains 4 ALLOW, 5 WARN, and 66 BLOCK images. When BLOCK represents 88% of any given image, a model needs to learn very little to approach perfect accuracy — correctly classifying BLOCK is almost sufficient. The 4 ALLOW and 5 WARN test samples are trivially separable because the v1 LLM assigned WARN only to images with zero critical CVEs, and ALLOW only to images that are near-completely clean. The decision tree reflects this:

```
|--- critical_cve_count <= 0.50
|   |--- vuln_total <= 5.00
|   |   |--- class: ALLOW       ← zero criticals, very few total vulns
|   |--- vuln_total > 5.00
|   |   |--- top25_cwe_count <= 11.00
|   |   |   |--- class: WARN    ← zero criticals, some moderate vulns
|   |   |--- top25_cwe_count > 11.00
|   |   |   |--- class: BLOCK   ← zero criticals, high CWE coverage
|--- critical_cve_count > 0.50
|   |--- class: BLOCK            ← any critical CVE → BLOCK (88% of all images)
```

This is not a security classifier — it is a rule-based threshold (any critical CVE → BLOCK) encoded into a Decision Tree with one extra leaf. The v1 prompt effectively reproduced the most aggressive possible threshold rule.

---

## v1 System Prompt — Root Cause Analysis

The v1 prompt defined BLOCK as:
> "One or more CRITICAL CVEs exist alongside systemic weakness breadth (elevated unique_cwe_count or top25_cwe_count)"

In practice, nearly every production image with any critical CVE also has non-zero `top25_cwe_count` and `unique_cwe_count`. The terms "one or more" and "elevated" have no numeric definition. The LLM correctly applied these criteria at face value, producing BLOCK for essentially any image with `critical_cve_count ≥ 1`.

The v1 prompt also defined WARN as requiring "no CRITICAL CVEs" — structurally eliminating WARN for any image with even a single isolated critical finding. This created a binary: critical CVE present → BLOCK; critical CVE absent → evaluate WARN or ALLOW.

Additional prompt deficiencies:
- No density or proportionality guidance (1 critical CVE in a 400-component image treated identically to 1 critical in a 5-component image)
- No operational framing emphasizing that BLOCK should be rare and over-blocking is a failure mode
- No numeric examples illustrating the WARN/BLOCK boundary

---

## Operational Assessment

A classifier that routes 88% of images to BLOCK is not functioning as a security gate — it is functioning as a reject queue. If deployed, developer trust in the pipeline would collapse within days as every merge triggers a BLOCK verdict on images that were otherwise considered production-ready. Engineers would bypass or disable the gate, defeating the purpose of the pipeline.

The 1.00 test accuracy is a vanity metric for this label distribution. A trivial classifier that always predicts BLOCK would achieve 88% accuracy — v0.0.5 only achieves 12 additional points by also correctly predicting 4 ALLOWs and 5 WARNs.

---

## What Changed Next

The v1 labeling anomalies drove a systematic prompt redesign. Key changes in `config/system-prompt-v2.md`:
- Replaced vague BLOCK qualifiers with concrete numeric anchors (`critical_cve_count ≥ 5`, or `≥ 2 AND max_cvss=10.0`)
- Expanded WARN to capture isolated critical CVEs in large images (`critical_cve_count` 1–4 with low density)
- Introduced vulnerability density framing ("weight findings relative to image size")
- Added operational language: "BLOCK should be rare; over-blocking trains developers to ignore the pipeline"
- Added 4 calibrated examples spanning the ALLOW/WARN/BLOCK spectrum

Full rationale: `analysis/llm-labeling-evaluation-v1-vs-v2.md`.

**→ v0.0.6** uses `gemini-2.5-flash` + `system-prompt-v2.md` and produces a substantially more realistic label distribution (ALLOW=21, WARN=100, BLOCK=250), though the distribution reveals a deeper structural insight: most production container images genuinely do not meet a strict ALLOW threshold.
