# Rule-Based Classification vs. Decision Tree: Design Rationale

Author: Alexander Castro
Date: 2026-03-23

---

## The Circular Labeling Problem

Using rule-based thresholds to generate training labels and then training a Decision Tree on those
labels produces a system that learns to approximate the rules — not the underlying ground truth of
security risk.

```
Rule thresholds → generate ALLOW/WARN/BLOCK labels
                         ↓
            DT trains on those labels
                         ↓
           DT learns to reproduce the rules
                         ↓
       DT evaluated against those same labels
                         ↓
  Evaluation reflects rule reproduction, not classification quality
```

The bucket selection (`high-qual`, `aged-stale`, `known-vuln`) provides a weak external signal, but
the final `ALLOW/WARN/BLOCK` labels within each bucket are entirely rule-derived. Breaking the
circularity requires independent human expert review of each image.

---

## Arguments For and Against Each Approach

### Rule-Based Thresholds

**For:**
- Feature medians show near-zero overlap across tiers — a DT would reconstruct cuts that already exist as readable constants
- At ~143 images, rules calibrated on medians are more statistically stable than a learned tree
- Thresholds are directly citable in security policy, SSDF documents, and audit reports
- No retraining pipeline, model versioning, or drift monitoring required

**Against:**
- Evaluates features independently — misses cases where a combination of sub-threshold values warrants escalation
- Adding features (e.g., Semgrep reintegration) requires manual threshold recalibration
- Override events cannot be absorbed automatically; require manual adjustment

### Decision Tree Classifier

**For:**
- Can learn compound-signal boundaries that no single threshold captures
- Absorbs human override corrections as training signal in retraining cycles
- Scales naturally with new features without manual recalibration

**Against:**
- Circular labeling: without independent ground-truth labels, the DT learns the rules, not actual risk
- 143 samples is insufficient for reliable generalization on a three-class imbalanced problem
- Internal splits require explicit export and annotation to satisfy auditability requirements

---

## The Scaling Argument

Breaking the circularity requires independent expert review of each image — labels assigned by a
security analyst based on contextual judgment, not the threshold system.

At ~143 images this is feasible. At one order of magnitude more (~1,400+ images) it becomes
operationally infeasible without a dedicated labeling team and protocol. Label quality also degrades
under time pressure, introducing noise that hurts a DT's generalization more than it hurts a rule
system's determinism.
