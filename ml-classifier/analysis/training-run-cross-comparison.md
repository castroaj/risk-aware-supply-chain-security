# Training Run Cross-Comparison

**Date:** 2026-04-11
**Runs analyzed:** `analysis/runs/20260411-094948`, `20260411-095044`, `20260411-095425`

---

## Summary of Results

| Metric | Run 1 (094948) | Run 2 (095044) | Run 3 (095425) |
|--------|---------------|---------------|---------------|
| Dataset size | 143 | 143 | 143 |
| Class dist (ALLOW / BLOCK / WARN) | 35 / 61 / 47 | 36 / 57 / 50 | 35 / 61 / 47 |
| Test Accuracy | **96.55%** | **89.66%** | **96.55%** |
| CV Accuracy | 92.32% ± 5.63% | 93.08% ± 7.22% | 92.32% ± 5.63% |
| ALLOW F1 | 1.00 | 1.00 | 1.00 |
| BLOCK F1 | 0.96 | 0.87 | 0.96 |
| WARN F1 | 0.95 | 0.86 | 0.95 |
| Root split feature | `top25_cwe_count` | `cvss_ge_7_count` | `top25_cwe_count` |

---

## Runs 1 and 3 Are Identical

Every metric, class distribution, and tree rule is the same across runs 1 and 3. This is expected and correct: `TrainingConfig.random_state=42` is hardcoded, and `train_test_split`, `DecisionTreeClassifier`, and `StratifiedKFold` all consume it. Given the same input data and the same seed, the pipeline is fully deterministic. Run 3 confirms reproducibility.

---

## Why Run 2 Diverges

Run 2 has a different class distribution despite loading the same 143 images:

- BLOCK: 61 → 57 (−4 images reclassified)
- WARN: 47 → 50 (+3)
- ALLOW: 35 → 36 (+1)

This cannot originate from the decision tree itself. The `rule_label` column is populated by `classify_metric()` inside `data_loader.load_bucket()` **at load time**, before any ML training. Between runs, some images fell near threshold boundaries for `critical_cve_count` or `top25_cwe_count`, causing them to flip class.

Because `top25_cwe_count` is the **root split** in runs 1/3, images near that boundary flip between BLOCK and WARN. With 4 fewer BLOCKs in training, the tree falls back to `cvss_ge_7_count` as the root — a structurally different decision boundary.

The CV accuracy is marginally higher in run 2 (93.08% vs 92.32%) but with greater variance (±7.22% vs ±5.63%), indicating some folds aligned favorably but the model is less stable. The 3.4 percentage point gap between CV and test accuracy in run 2 (vs 0.23% in runs 1/3) signals that the test partition contains proportionally harder edge cases under the label set run 2 trained on.

---

## Effectiveness Against the Mission

The mission is a **security gate that defaults to caution** — missing a BLOCK is more dangerous than over-blocking a WARN.

### ALLOW (F1=1.00 across all runs)
High-quality images have distinct feature signatures and pose no classification challenge. This class is not a concern.

### BLOCK — runs 1/3 (F1=0.96)
Recall=0.92 means 1 BLOCK in the 29-sample test set was misclassified as WARN — an image that should be blocked would instead reach a human reviewer with only a warning. Precision=1.00 means no false positives (no WARNs called BLOCK), which is good for pipeline throughput.

### BLOCK — run 2 (F1=0.87)
Recall drops to 0.83 — approximately 2 BLOCKs out of 12 are being labeled WARN. This is materially worse for a security use case. Precision=0.91 means some WARN images are also being escalated to BLOCK. Both error directions are present simultaneously, indicating the BLOCK/WARN decision boundary is poorly calibrated when the training label set drifts.

### WARN
Near-perfect recall in runs 1/3 (all WARNs correctly caught). In run 2, precision drops as BLOCKs bleed into the WARN bucket, the inverse of the BLOCK degradation above.

### CV Variance
The ~5-7% standard deviation across folds on 143 samples reflects a small dataset. Each fold contains only ~28 test samples, making per-fold accuracy highly sensitive to which specific images land in each partition. This masks the true generalization capability of the model.

---

## Actionable Improvements

### P0 — Data Pipeline Reliability

**1. Decouple label generation from training**
Persist rule labels as a CSV artifact at scan time, not inside `load_bucket()` at training time. Training should consume this pre-labeled CSV rather than re-evaluating `classify_metric()` on every run. Label drift becomes immediately visible as a diff between scan-time labels and current labels, rather than silently degrading model performance.

**2. Save the full feature DataFrame as a per-run artifact**
Each run currently saves only `pkl` files and a text report. Adding the labeled `DataFrame` as a `dataset_snapshot.csv` per run enables exact recreation of any run and makes it trivial to diff run 2 against runs 1/3 to identify which 4 images changed labels and why.

---

### P1 — Dataset Quality

**5. Increase dataset size**
143 images is small for a three-class problem. CV variance of ±5-7% is a direct symptom — each fold has ~28 test samples. Target 400-500+ images to bring CV standard deviation below ±3%. Prioritize images that fall near classification boundaries (moderate age, moderate CVE counts), as these are where current misclassifications occur.

**6. Add a truly held-out validation set**
All 143 images are currently used in both training and cross-validation, giving a somewhat optimistic CV estimate. Carve out 20-30 images (stratified by class) before any training run and never train on them. This provides a third, uncontaminated estimate of generalization performance.

**7. Version-control the threshold constants**
`BLOCK_THRESHOLDS` and `WARN_THRESHOLDS` in `sbom_extractor.py` directly determine what labels the tree trains against. Any threshold change silently relabels all training data. These should be hashed into the run artifact so future runs can detect when thresholds changed and flag the dataset as invalidated.

---

### P2 — Model Quality

**8. Bias the cost matrix toward BLOCK false negatives**
`class_weight="balanced"` weights classes inversely proportional to frequency. For a security gate, BLOCK misses are significantly more costly than WARN false positives. Consider `class_weight={"ALLOW": 1, "WARN": 2, "BLOCK": 4}` to improve BLOCK recall at an acceptable precision cost. This was experimentally evaluated on 2026-04-12 — see `spec/class-weight-tuning-spec.md` for full results and conditions under which re-evaluation is warranted.

**9. Address correlated features**
`critical_cve_count`, `high_cve_count`, `cvss_ge_7_count`, and `vuln_total` all measure overlapping aspects of vulnerability severity. High pairwise correlation between these features makes split selection noisy — any one can serve as the root split under slightly different data, as demonstrated by the run 2 pivot from `top25_cwe_count` to `cvss_ge_7_count`. Consider computing a single composite severity score or removing `cvss_ge_7_count`, which is effectively captured by the combination of critical and high counts.

**10. Plan Semgrep feature integration**
Runs 1/3 achieve 96.55% test accuracy with 9 features but still produce 1 BLOCK miss per test set. Adding SAST features (`semgrep_total`, `semgrep_high_count`) per the deferred scope would sharpen the BLOCK/WARN boundary — source-level findings often distinguish these two classes more crisply than vulnerability counts alone, particularly for images with patched CVEs but unreviewed source code.
