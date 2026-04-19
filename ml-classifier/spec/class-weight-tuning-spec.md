# class_weight Tuning Specification

**Component:** `src/classifier/trainer.py` — Risk-Aware Supply Chain Security
**Author:** Alexander Castro
**Date:** 2026-04-12

---

## 1. Problem Statement

`class_weight="balanced"` weights classes inversely proportional to their frequency in the training set. Because BLOCK is the majority class (61/143 = 42.7%), "balanced" assigns it the **lowest** effective weight (~0.78×) and ALLOW the highest (~1.36×):

| Class | Samples | Effective weight under "balanced" |
|-------|---------|----------------------------------|
| ALLOW | 35 | 143 / (3 × 35) ≈ 1.36× |
| WARN  | 47 | 143 / (3 × 47) ≈ 1.01× |
| BLOCK | 61 | 143 / (3 × 61) ≈ 0.78× |

For a security gate this is backwards: a missed BLOCK (false negative) allows a dangerous image through to production, while a spurious BLOCK (false positive) only increases human review load. BLOCK misclassifications should be penalized more heavily than ALLOW or WARN misclassifications during training.

---

## 2. Proposed Scheme

```
class_weight = {"ALLOW": 1, "WARN": 2, "BLOCK": 4}
```

This makes BLOCK misclassifications 4× more expensive than ALLOW misclassifications during tree construction, biasing split selection toward avoiding BLOCK false negatives.

The CLI accepts this as a JSON string:

```bash
risk-classifier-train \
    --labels-dir data/labels/ \
    --output-dir training-runs/ \
    --class-weight '{"ALLOW":1,"WARN":2,"BLOCK":4}'
```

---

## 3. Experiment Results

**Date:** 2026-04-12
**Runs:** `analysis/runs/cw-balanced/`, `analysis/runs/cw-block4/`
**Dataset:** 143 images, labels frozen in `data/labels/`

| Metric | cw-balanced | cw-block4 |
|--------|-------------|-----------|
| Dataset size | 143 | 143 |
| Class dist (ALLOW / BLOCK / WARN) | 35 / 61 / 47 | 35 / 61 / 47 |
| Test Accuracy | 96.55% | 96.55% |
| CV Accuracy | 92.32% ± 5.63% | 92.27% ± 7.31% |
| ALLOW precision / recall / F1 | 1.00 / 1.00 / 1.00 | 1.00 / 1.00 / 1.00 |
| BLOCK precision / recall / F1 | 1.00 / 0.92 / 0.96 | 1.00 / 0.92 / 0.96 |
| WARN precision / recall / F1 | 0.91 / 1.00 / 0.95 | 0.91 / 1.00 / 0.95 |

**Finding:** Every per-class metric is identical across both runs. The confusion matrix is the same: 1 BLOCK is misclassified as WARN in both cases.

---

## 4. Interpretation

The custom class_weight has no measurable effect on this dataset. This is expected given how the training data is constructed:

1. **Labels are mechanically derived from thresholds.** `classify_metric()` applies `BLOCK_THRESHOLDS` / `WARN_THRESHOLDS` constants to assign `rule_label`. The resulting class boundaries are extremely clean — BLOCK images exceed threshold constants by large margins, not by small amounts.

2. **The tree fits cleanly at depth ≤ 5.** With near-deterministic boundaries, the DecisionTree achieves near-perfect purity regardless of how misclassification costs are weighted. There are few or no ambiguous near-boundary samples for the weighting to reshape.

3. **The one remaining BLOCK miss is irreducible at this depth.** The tree does not have a split path that correctly routes that sample under any weighting scheme — additional depth or additional features are required.

`class_weight` tuning is irrelevant when labels are mechanically derived from the same thresholds used to partition the training data. The weighting only becomes meaningful when:

- Labels carry genuine ambiguity (noisy scans, human curation, near-boundary images with mixed signals)
- The dataset is large enough that many near-boundary samples exist on both sides of each split candidate

---

## 5. Cost/Benefit Summary

| Trade-off | Impact |
|-----------|--------|
| BLOCK recall increase | None observed on current dataset |
| BLOCK precision decrease | None observed on current dataset |
| WARN → BLOCK false positive rate increase | None observed on current dataset |
| Overall accuracy change | None |
| CV variance change | +1.68% std (92.32% ± 5.63% → 92.27% ± 7.31%) — marginal, within noise |

**Verdict:** The scheme is theoretically justified but currently pre-emptive. It produces no measurable harm and leaves a correct conceptual bias in place for when the dataset evolves.

---

## 6. Conditions for Re-evaluation

Re-run this comparison when **any** of the following are true:

- Dataset grows beyond ~400 samples
- Labels are partially or fully human-annotated (introducing genuine boundary ambiguity)
- A held-out validation set is established (enabling uncontaminated evaluation of the recall/precision trade-off)
- SAST features (`semgrep_total`, `semgrep_high_count`) are integrated, potentially creating new BLOCK/WARN boundary cases

At that point, use `class_weight={"ALLOW":1,"WARN":2,"BLOCK":4}` as the baseline and sweep from there (e.g., `{"ALLOW":1,"WARN":2,"BLOCK":8}`).

---

## 7. Implementation Notes

**Files changed to enable `--class-weight` CLI flag:**

| File | Change |
|------|--------|
| `src/classifier/trainer.py:25` | Added `Union` to typing imports |
| `src/classifier/trainer.py:73` | `class_weight: Union[str, dict] = "balanced"` |
| `src/classifier/trainer.py:592-607` | Translates string dict keys → LabelEncoder integer keys before passing to sklearn |
| `src/classifier/cli.py` | Added `--class-weight SCHEME` argument; parses JSON dict or string |

**sklearn requirement:** `DecisionTreeClassifier` requires dict keys to be the encoded integer class labels (0, 1, 2), not class name strings. The trainer translates `{"ALLOW": 1, "WARN": 2, "BLOCK": 4}` → `{0: 1, 1: 4, 2: 2}` via the fitted `LabelEncoder` before constructing the classifier.
