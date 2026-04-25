# Technical Critique

This document is intended for contributors and developers. It is a candid assessment of the current system's weaknesses—not for external audiences. Each item identifies a specific flaw, explains why it matters, and proposes a concrete mitigation path.

---

## 1. Training labels are circular

The Decision Tree is trained on labels produced by rule-based thresholds. The ML model essentially learns to reproduce those thresholds—it is not learning any independent signal. This means the 97.33% test accuracy reflects how well the tree approximates the rule logic, not how well either the rules or the tree reflects actual deployment risk.

**Mitigation:** Ground truth labels should come from actual deployment outcomes—post-deployment incident data, security team escalations, or red-team findings correlated back to SBOM features. Even 50–100 expert-labeled images with documented rationale would allow the model to generalize beyond threshold approximation. Until then, the ML layer adds computational overhead but not epistemic value beyond the rule-based classifier itself.

---

## 2. Dataset is small and class-imbalanced

371 images with 45 in the BLOCK class (12%) is a thin training corpus for a production security decision. Class weighting (`BLOCK:4`) partially compensates, but the model is vulnerable to distributional shift: a new class of vulnerability pattern not represented in those 45 images may not be classified correctly.

**Mitigation:** Expand the known-vuln bucket aggressively (Docker Hub pull budget is the constraint, not the supply of known-vulnerable images). Public vulnerability databases (VulnDB, OSV, NVD advisories) can identify hundreds of historically vulnerable image:tag pairs. Synthetic augmentation of borderline cases near threshold boundaries would also reduce sensitivity of the decision boundary to individual data points.

---

## 3. Feature vector excludes temporal signals

Image age, time since last rebuild, and time since a vulnerability was first published are not features in the current vector. Yet age is the primary distinguishing factor between the ALLOW and WARN buckets by construction (the WARN bucket was built from images 6 months–2 years old). This leaks the bucket-construction logic into the model rather than capturing a generalizable risk signal.

**Mitigation:** Add `days_since_image_pushed` or `days_since_oldest_vuln_published`. Trivy's vulnerability output includes `published_date` fields; SBOM metadata includes image creation timestamp. Both are extractable from existing artifacts without additional tooling.

---

## 4. `max_cvss` is near-zero variance and provides no information gain

Across all three training buckets, the median `max_cvss` is 10.0. A single critical CVE in an otherwise clean image and an image with 500 critical CVEs both produce `max_cvss = 10.0`. The feature has near-zero variance and near-zero information gain for the Decision Tree—yet it appears in the feature vector and the correlation matrix.

**Mitigation:** Replace with `mean_cvss_of_criticals` or `percentile_90_cvss` to capture the shape of the severity distribution rather than its ceiling. Alternatively, drop `max_cvss` from the feature vector entirely and validate that model accuracy is unaffected (it should be).

---

## 5. SAST features are permanently absent for third-party images

The design documents Semgrep-based SAST features (`semgrep_total`, `semgrep_high_count`) but these are zero across the entire dataset because pre-built public images have no source code available at scan time. This is not a temporary implementation gap—it is a categorical scope mismatch. The feature vector therefore has no application-layer signal; it is entirely infrastructure-layer CVE counts.

**Short-term mitigation:** For images with OCI source labels, extract `org.opencontainers.image.source` and `org.opencontainers.image.revision` from the SBOM metadata, clone the pinned commit, and run Semgrep. Automatable for well-labeled official images; adds genuine application-layer signal for a meaningful subset.

**Long-term mitigation:** Formally separate Use Case A (third-party image evaluation—current scope) from Use Case B (first-party build pipeline with source code available). Use Case B is where SAST features belong. The current design conflates both in ways that weaken each.

---

## 6. No automated drift detection or retraining trigger

The pipeline has no mechanism to detect when the model's decision distribution has shifted relative to the rule-based baseline or real-world outcomes. Model versions are managed manually in timestamped directories. A model trained months ago on a different vulnerability landscape may silently degrade.

**Mitigation:** Implement a lightweight drift detector in `Predictor`: compare incoming feature vectors against the training distribution using Mahalanobis distance or an isolation forest. Flag out-of-distribution predictions as low-confidence regardless of the tree's output. Requires no ground-truth labels and fits cleanly into the existing prediction path. Retraining should be triggered at minimum when newly disclosed known-vulnerable images are found to be misclassified by the current model.

---

## 7. Escalation policy threshold is a heuristic, not a calibrated value

The 0.75 confidence threshold for WARN→BLOCK escalation is not derived from data—it is a conservative default. Decision Trees are not inherently well-calibrated; leaf-node probability estimates reflect training sample ratios rather than true likelihoods, and a tree with `max_depth=5` may be systematically overconfident or underconfident in specific regions of the feature space.

**Mitigation:** Apply Platt scaling or isotonic regression to calibrate the tree's probability outputs, or wrap the Decision Tree in `CalibratedClassifierCV` (scikit-learn) at training time. The 0.75 threshold can then be derived empirically from a calibration curve on held-out validation data rather than chosen by intuition.
