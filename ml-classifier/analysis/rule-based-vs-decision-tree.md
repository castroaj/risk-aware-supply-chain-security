# Rule-Based Classification vs. Decision Tree: Design Rationale

Author: Alexander Castro
Date: 2026-03-23

---

## Background

The original classification proposal (`research/ML_model/classification-proposal.md`) specified a
supervised Decision Tree classifier trained on labeled feature vectors extracted from CycloneDX SBOMs.
The rule-based threshold system implemented in `src/sbom_extractor.py` was intended as an interim
step — a labeling mechanism to generate training data for that model.

This document records the analysis of whether the rule-based system should replace the Decision Tree
as the permanent classifier, and why that decision is sound.

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
      Artificially high accuracy / F1 scores
```

Consequences:

- **The DT can never outperform the rules on in-distribution data.** It is approximating its own
  teacher. Any accuracy metric computed on rule-labeled data measures how well the DT mimics the
  rules, not how well either system classifies actual risk.
- **Evaluation metrics become meaningless.** Precision, recall, and confusion matrices on this
  dataset reflect rule reproduction fidelity, not classification quality.
- **The primary benefit of supervised learning is eliminated.** The value of a DT is discovering
  non-obvious decision boundaries that human rule-writers miss. Labels derived from those rules
  give the model nothing novel to discover.

The bucket selection (`high-qual`, `aged-stale`, `known-vuln`) represents a weaker form of external
signal — those images were chosen based on criteria independent of the threshold system. However,
the final `ALLOW/WARN/BLOCK` labels within each bucket are entirely rule-derived. Independent
human security expert review of each image would be required to break the circularity.

---

## Arguments For and Against Each Approach

### Rule-Based Thresholds

**For:**

- **Feature separations are already clean.** The statistics in `dataset-statistics.md` show
  near-zero overlap between ALLOW and WARN/BLOCK medians for dominant features:
  `base_image_age_days` (medians: 47 / 1627 / 2683), `critical_cve_count` (medians: 1 / 32 / 56).
  A DT trained on this data would reconstruct axis-aligned cuts that already exist as
  human-readable constants.
- **Dataset size disfavors a DT.** At ~143 images (57 / 55 / 31), a DT is at constant risk of
  overfitting the training split. Rules calibrated on medians are statistically more stable.
- **Auditability and compliance.** A threshold like `critical_cve_count ≥ 50 → BLOCK` is
  directly citable in a security policy, SSDF document, or audit report. A DT's internal splits
  require explicit export and annotation to defend to a non-technical reviewer.
- **Operational simplicity.** Rules require only a code review and documentation update to
  change. A DT requires a full retraining pipeline, model artifact versioning, drift monitoring,
  and a promotion process.
- **Domain knowledge is already encoded.** Feature exclusion decisions (dropping `max_cvss`,
  `vuln_total`, `high_cve_count`) reflect security domain judgment that a DT would have to
  rediscover — and might not, given the sample size.

**Against:**

- **No compound-signal reasoning.** Rules evaluate features independently. A DT can learn that
  a combination of moderate values — e.g., `critical_cve_count` = 8 (below WARN threshold),
  `cvss_ge_7_count` = 80 (below WARN threshold), `top25_cwe_count` = 40 (below WARN threshold)
  — constitutes a WARN when no individual rule fires. This is the primary failure mode of
  independent threshold logic.
- **Rules don't scale with feature additions.** Adding new features (e.g., Semgrep reintegration)
  requires manual recalibration of all thresholds for feature interactions. A DT handles this
  during training.
- **Override events are not absorbed.** Human-in-the-loop corrections cannot feed back into
  rule calibration automatically; they require manual threshold adjustment.

### Decision Tree Classifier

**For:**

- **Compound-signal boundary learning.** Can identify that combinations of individually
  sub-threshold features warrant escalation, a capability rules cannot express without
  combinatorial explosion.
- **Scales with feature additions.** Reintegrating deferred features (Semgrep) or adding new
  signal sources does not require manual threshold recalibration.
- **Override feedback loop.** Human review corrections become training signal for retraining
  cycles.
- **Accurate WARN boundary modeling.** The current 19 WARNs in `high-qual` and 3 WARNs in
  `known-vuln` represent boundary cases that a DT could model more accurately than fixed thresholds.

**Against:**

- **Circular labeling (see above).** Without independent ground-truth labels, training produces
  a rule approximator, not a risk classifier.
- **Small dataset.** 143 samples is insufficient for reliable generalization, particularly for
  a three-class problem with an imbalanced WARN class.
- **Explainability overhead.** Compliance and audit requirements favor transparent, citable
  decision logic over an exported tree that requires documentation to interpret.

---

## The Scaling Argument

Breaking the circular labeling problem requires independent expert review of each training image —
labels assigned by a security analyst based on contextual judgment, not by running the threshold
logic.

At the current dataset size (~143 images) this is feasible. At one order of magnitude more (~1,400+
images) it becomes operationally infeasible without a dedicated security team and an explicit
labeling protocol. Label quality also degrades under time pressure — rushed or inconsistent labels
introduce noise that hurts a DT's generalization more than it hurts a rule system's determinism.

Alternative approaches that reduce manual burden at scale exist:

- **Programmatic labeling** (e.g., Snorkel-style weak supervision): treats rules as noisy labeling
  functions and trains a generative model to reconcile them. Partially addresses circularity but adds
  significant infrastructure complexity.
- **Active learning**: prioritizes the most informative samples for human review, reducing the total
  labeling budget. Requires iterative tooling and still needs an initial independent labeled set.

Neither alternative eliminates the core requirement for some independent ground-truth labels. The
scaling constraint removes the last viable path to obtaining those labels within this project's scope.
