# Project Brief: Risk-Aware ML-Gated Supply Chain Security

## The Problem

Software supply chain attacks have become a dominant threat vector. Attackers increasingly compromise widely-used container images, libraries, and build artifacts rather than targeting end-user systems directly. The 2021 SolarWinds and Log4Shell incidents demonstrated that a single vulnerable dependency can cascade across thousands of downstream deployments within hours.

CI/CD pipelines are the last automated gate before code reaches production, yet most existing pipelines fail at supply chain risk in two ways:

1. **Binary enforcement without nuance.** Tools like Trivy or Grype return raw vulnerability lists, and pipelines either fail on *any* critical CVE (generating massive false-positive noise that erodes developer trust) or pass everything through (providing no meaningful security gate).

2. **No audit trail or governance layer.** Even when scans run, the decision logic—which vulnerabilities matter, why the build was allowed, who approved an exception—is often absent, making compliance attestation impossible.

The gap is not in scanning capability; mature open tools exist. The gap is in the **risk translation layer**: converting structured vulnerability data into an explainable, auditable, policy-consistent deployment decision.

---

## The Approach

This project implements a four-stage ML pipeline that acts as that translation layer:

**Stage 1 — Scan.** Trivy scans container images and produces CycloneDX-format SBOMs containing components and vulnerability data. The SBOM is the canonical artifact; everything downstream is derived from it.

**Stage 2 — Extract.** A feature extractor parses the CycloneDX JSON and produces a fixed 8-feature vector: `total_dependency_count`, `vuln_total`, `critical_cve_count`, `high_cve_count`, `cvss_ge_7_count`, `max_cvss`, `unique_cwe_count`, `top25_cwe_count`. Severity ratings take the highest score across all databases per CVE. CWE membership is checked against the MITRE Top 25 (2025) list.

**Stage 3 — Label (training only).** Rule-based thresholds derived from statistical analysis of 371 labeled container images assign each image to ALLOW, WARN, or BLOCK. Labels are frozen in version-controlled CSVs so threshold changes produce visible diffs rather than silent accuracy shifts.

**Stage 4 — Classify.** A Decision Tree trained on those labeled CSVs (97.33% test accuracy, 96.96% ± 1.97% 5-fold CV) produces the final risk decision. A confidence-based escalation policy promotes uncertain WARN predictions (confidence < 0.75) to BLOCK. Human reviewers retain override authority; all decisions, confidence scores, and overrides are logged for audit.

Training dataset breakdown: 172 well-maintained images (ALLOW), 154 aged/stale images (WARN), 45 known-vulnerable images (BLOCK).

---

## Why This Research Is Valuable

**Interpretability over accuracy.** Decision Trees produce human-readable split rules. Security engineers can audit exactly which feature values triggered a BLOCK without reverse-engineering a neural network. This is not an academic preference—it is a compliance requirement in regulated industries. An explainable model that auditors can inspect is worth more than a more accurate opaque one.

**Risk translation reduces alert fatigue.** The system does not simply count CVEs; it contextualizes them. A single critical CVE in an otherwise clean image is different from a hundred low-severity CVEs across hundreds of stale dependencies. Translating raw counts into ALLOW/WARN/BLOCK with documented thresholds reduces the noise that causes developers to disable security gates.

**Frozen labels + version control = reproducible governance.** Committing labeled CSVs to Git means every training run can be reproduced, every threshold change is visible in history, and every model version traces back to a specific labeled dataset. This is the supply chain security principle applied to the model's own training data.

**Pipeline-native integration.** The classifier is not a standalone tool—it is a CI/CD gate. The design explicitly places a human in the loop with override capability and full audit logging, fitting the actual governance model of most organizations (security team approves; engineers ship) rather than requiring full automation.

**Generalizability of the feature vector.** The 8 features cover orthogonal axes of supply chain risk: vulnerability volume (total count), severity ceiling (max CVSS), severity distribution (critical/high counts, CVSS ≥ 7), attack surface (dependency count), weakness breadth (unique CWEs), and exploitation likelihood (MITRE Top 25 CWEs). This framing is applicable beyond container images to any software artifact with a scannable SBOM.

---

## Flaws and How They Could Be Tackled

### 1. The training labels are circular

The Decision Tree is trained on labels produced by rule-based thresholds. The ML model essentially learns to reproduce those thresholds—it is not learning any independent signal. This means the classifier's accuracy metric (97.33%) reflects how well the tree approximates the rule logic, not how well either the rules or the tree reflects actual deployment risk.

**Mitigation:** Ground truth labels should come from actual deployment outcomes—post-deployment incident data, security team escalations, or red-team findings correlated back to SBOM features. Even a small set of ground-truth-labeled images (50–100 with documented rationale) would allow the model to generalize beyond threshold approximation. Until then, the ML layer adds computational overhead but not epistemic value beyond the rule-based classifier itself.

### 2. The dataset is small and class-imbalanced

371 images with 45 in the BLOCK class (12%) is a thin training corpus for a production security decision. Class weighting (`BLOCK:4`) partially compensates, but the model is vulnerable to distributional shift: a new class of vulnerability pattern not represented in those 45 images may not be correctly classified.

**Mitigation:** Expand the known-vuln bucket aggressively (the Docker Hub pull budget is the constraint, not the supply of known-vulnerable images). Public vulnerability databases (VulnDB, OSV, NVD advisories) can identify hundreds of historically vulnerable image:tag pairs. Additionally, synthetic augmentation of borderline cases (images near threshold boundaries) would reduce the sensitivity of the decision boundary to individual data points.

### 3. The feature vector excludes temporal signals

An image's age, the time since its last rebuild, and the time since its vulnerability was first published are not features in the current vector. Yet age is the primary distinguishing factor between the ALLOW and WARN buckets by construction (the WARN bucket was built from images 6 months–2 years old). This leaks the bucket-construction logic into the model rather than capturing a true risk signal.

**Mitigation:** Add `days_since_image_pushed` or `days_since_oldest_vuln_published` as features. Trivy's vulnerability output includes `published_date` fields; the SBOM metadata includes image creation timestamp. These are extractable from existing artifacts without additional tooling.

### 4. `max_cvss` is nearly useless as a feature

Across all three training buckets, the median `max_cvss` is 10.0. A single critical CVE in an otherwise clean image and an image with 500 critical CVEs both produce `max_cvss = 10.0`. The feature has near-zero variance and thus near-zero information gain for the Decision Tree—yet it is in the feature vector and included in the correlation matrix.

**Mitigation:** Replace or supplement `max_cvss` with `mean_cvss_of_criticals` or `percentile_90_cvss`. These capture the shape of the severity distribution rather than just its ceiling, providing genuine discriminative signal. Alternatively, drop `max_cvss` from the feature vector entirely and validate that model accuracy is unaffected.

### 5. SAST features are permanently absent for third-party images

The design documents Semgrep-based SAST features (`semgrep_total`, `semgrep_high_count`) but these are zero across the entire dataset because pre-built public images have no source code available at scan time. This is not a temporary implementation gap—it is a categorical scope mismatch. The feature vector therefore has no application-layer signal at all; it is entirely infrastructure-layer (CVE counts).

**Mitigation (short-term):** For images with OCI source labels, extract the `org.opencontainers.image.source` + `org.opencontainers.image.revision` metadata from the SBOM, clone the pinned commit, and run Semgrep against it. This is automatable for well-labeled official images and would add genuine application-layer signal for a meaningful subset of the dataset.

**Mitigation (long-term):** Formalize the split between Use Case A (third-party image evaluation, current scope) and Use Case B (first-party build pipeline where source code is available). Use Case B unlocks the full intended feature vector and is where SAST features actually belong. The current design conflates these two use cases in ways that weaken both.

### 6. No automated drift detection or retraining trigger

The pipeline has no mechanism to detect when the model's decision distribution has shifted relative to the rule-based baseline or to real-world outcomes. Model versions are manually managed in timestamped directories. A model trained six months ago on a different vulnerability landscape may silently degrade.

**Mitigation:** Implement a lightweight drift detector that runs during prediction: if the feature vector of an incoming SBOM falls significantly outside the training distribution (e.g., using Mahalanobis distance or isolation forest on the 8-feature space), flag the prediction as low-confidence regardless of the tree's output. This requires no ground-truth labels and can be integrated into the existing `Predictor` class. Retraining should be triggered at minimum when new known-vulnerable images are publicly disclosed that the current model would misclassify.

### 7. The escalation policy is a heuristic, not a calibrated threshold

The 0.75 confidence threshold for WARN→BLOCK escalation is not derived from data—it is a conservative default. Decision Trees are not inherently well-calibrated classifiers; their leaf-node probability estimates reflect training sample ratios rather than true likelihoods, and a tree with `max_depth=5` may produce confidence scores that are systematically overconfident or underconfident in specific regions of the feature space.

**Mitigation:** Apply Platt scaling or isotonic regression to calibrate the tree's probability outputs before applying the confidence threshold. Alternatively, wrap the Decision Tree in a `CalibratedClassifierCV` (available in scikit-learn) at training time. The 0.75 threshold can then be empirically derived from a calibration curve on held-out validation data rather than chosen by intuition.

---

## Summary Assessment

The project successfully demonstrates an interpretable, auditable risk translation layer for supply chain security in CI/CD pipelines. The pipeline architecture, feature engineering rationale, label versioning strategy, and governance model are all sound and production-oriented. The core scientific weakness is that the ML model is currently learning to approximate its own training rules rather than learning from independent risk ground truth—making its accuracy a measure of self-consistency rather than real-world validity. Resolving this requires either richer ground-truth labeling from operational data or the temporal and distributional features that would allow the model to generalize beyond threshold reproduction.
