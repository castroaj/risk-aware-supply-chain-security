# Project Brief: Risk-Aware ML-Gated Supply Chain Security

## Problem

Software supply chain attacks have become a dominant threat vector. Attackers increasingly compromise widely-used container images, libraries, and build artifacts rather than targeting end-user systems directly. The 2021 SolarWinds and Log4Shell incidents demonstrated that a single vulnerable dependency can cascade across thousands of downstream deployments within hours.

CI/CD pipelines are the last automated gate before code reaches production, yet most existing pipelines fail at supply chain risk in two ways:

1. **Binary enforcement without nuance.** Vulnerability scanners return raw CVE lists, and pipelines either fail on *any* critical finding—generating false-positive noise that erodes developer trust—or pass everything through with no meaningful security gate.

2. **No audit trail or governance layer.** Even when scans run, the decision logic—which vulnerabilities matter, why the build was allowed, who approved an exception—is often absent, making compliance attestation impossible.

The gap is not in scanning capability; mature open tools exist. The gap is in the **risk translation layer**: converting structured vulnerability data into an explainable, auditable, policy-consistent deployment decision.

---

## Foundation

Solving this problem has direct policy backing. Executive Order 14028 (May 2021) mandated Software Bills of Materials for all software procured by the federal government, establishing SBOMs as a compliance artifact rather than an optional best practice. This creates a concrete, regulatory-grounded rationale for building systems that consume and reason over SBOM data.

The tools chosen for this system were each selected to address a specific constraint:

**SBOMs** are the key architectural choice. A raw vulnerability scanner produces a point-in-time list of findings. An SBOM is a persistent, queryable artifact: when a new CVE is published after a build, existing SBOMs can be queried retroactively without re-scanning the image. More importantly for this system, an SBOM is structured data—it can be parsed, feature-extracted, and fed into a classifier. A raw scanner report cannot.

**CycloneDX** is the OWASP-governed SBOM standard designed specifically for security use cases, in contrast to SPDX which is optimized for license compliance. Its JSON encoding allows direct programmatic extraction with standard libraries, and it unifies component inventory and vulnerability data in a single document. This is what makes the feature extraction stage tractable.

**Trivy** produces both the SBOM and the vulnerability scan in a single pass, reducing pipeline complexity and eliminating any mismatch between what was inventoried and what was scanned. It is open-source with no license barrier, which matters for research reproducibility, and it outputs CycloneDX natively without a conversion step.

**GitHub Actions** is where build decisions already happen. Security analysis inserted at the CI/CD layer runs at the exact moment an artifact is promoted—before it reaches a registry or a production environment—without requiring a separate platform or developer behavior change. Its artifact retention mechanism provides the audit log infrastructure for free.

**A machine learning classifier** rather than purely a static ruleset addresses the central limitation of threshold-based systems: rules do not adapt. As the vulnerability landscape evolves, manually maintained cutoffs drift out of calibration with real-world risk. A classifier trained on labeled examples generalizes across the interaction of features—an image with a moderate CVE count but unusually dangerous weakness types can be flagged even if no single threshold is breached. A Decision Tree specifically was chosen because interpretability is not optional here: every BLOCK decision must be explainable to the developer appealing it and to the auditor reviewing the log. A model that cannot be read is a model that cannot be trusted.

---

## Approach

This project implements a four-stage ML pipeline that acts as that translation layer:

**Stage 1 — Scan.** Trivy scans container images and produces CycloneDX-format SBOMs containing components and vulnerability data. The SBOM is the canonical artifact; everything downstream is derived from it.

**Stage 2 — Extract.** A feature extractor parses the CycloneDX JSON and produces a fixed 8-feature vector: 

- `total_dependency_count` 
- `vuln_total`
- `critical_cve_count`
- `high_cve_count`
- `cvss_ge_7_count`
- `max_cvss`
- `unique_cwe_count`
- `top25_cwe_count` 

Severity ratings take the highest score across all databases per CVE. CWE membership is checked against the MITRE Top 25 (2025) list. The 8 features cover orthogonal axes of risk: vulnerability volume, severity ceiling, severity distribution, attack surface, weakness breadth, and exploitation likelihood.

**Stage 3 — Label.** Rule-based thresholds derived from statistical analysis of 371 labeled container images assign each image to ALLOW, WARN, or BLOCK. Labels are frozen in version-controlled CSVs so threshold changes produce visible diffs rather than silent accuracy shifts—applying the supply chain integrity principle to the model's own training data.

**Stage 4 — Classify.** A Decision Tree trained on those labeled CSVs (97.33% test accuracy, 96.96% ± 1.97% 5-fold CV) produces the final risk decision. A confidence-based escalation policy promotes uncertain WARN predictions (confidence < 0.75) to BLOCK. Human reviewers retain override authority; all decisions, confidence scores, and overrides are logged for audit.

Training dataset: 172 well-maintained images (ALLOW), 154 aged/stale images (WARN), 45 known-vulnerable images (BLOCK).

---

## Results

Model development has proceeded iteratively, with each version addressing a specific weakness identified in the previous round. Detailed metrics and artifacts are preserved in `ml-classifier/model-results/`.

**Initial Prototype** established that the pipeline was feasible. The classifier could separate ALLOW from BLOCK reliably, but the WARN class—images that fall between clearly safe and clearly dangerous—was its weakest point. This run confirmed the architecture worked and identified deliberate model design as the next priority.

**model-0.0.1** introduced structured hyperparameters and added image age as a temporal feature. The tree reorganized around age as its primary decision point and WARN performance improved substantially. The remaining concern was high variance across cross-validation folds, signaling that 143 training images were not enough to produce a stable model.

**model-0.0.2** addressed that directly with a major dataset expansion—143 to 371 images. Cross-validation variance dropped significantly, confirming the instability had been a data quantity problem rather than a modeling one.

**model-0.0.3** introduced two conceptual shifts. Image age was removed from the feature vector: although it was a strong predictor, it was strong for the wrong reason—the WARN bucket had been built from images in a specific age range, so the model was learning dataset construction logic rather than generalizable risk signal. Class weighting was also changed from balanced to asymmetric, explicitly encoding the fact that a missed threat carries a higher cost than a false alarm. Alongside these changes, a set of borderline images were recalibrated from WARN to ALLOW after the WARN thresholds were found to be too aggressive for moderate-risk profiles.

**model-0.0.4** *(current)* continued that label refinement and introduced a confidence-based escalation policy: WARN predictions below a confidence threshold are automatically promoted to BLOCK, embedding cost asymmetry directly into the inference path rather than relying solely on training weights. The result is the cleanest tree structure to date and the strongest overall accuracy at 97.33%, with the WARN class reaching perfect classification on the test set.

---

## Next Steps

The current system establishes a working, interpretable pipeline and proves the viability of ML-gated deployment decisions. Several high-value extensions would substantially strengthen both the scientific contribution and practical coverage.

**Operational ground-truth labeling.** Replacing rule-derived labels with labels grounded in real deployment outcomes—post-deployment incidents, security team escalations, red-team findings—would allow the model to learn independent risk signal rather than approximate its own training rules. Even a curated set of 50–100 expert-labeled images with documented rationale would meaningfully improve the model's external validity.

**Dataset expansion.** Public vulnerability databases (OSV, NVD advisories, VulnDB) can identify hundreds of historically vulnerable image:tag pairs. Expanding the BLOCK class in particular, which currently holds only 45 images, would reduce sensitivity to distributional shift when new vulnerability patterns emerge.

**Temporal feature enrichment.** Image age, time-since-last-rebuild, and days-since-vulnerability-published are extractable from existing artifacts (Trivy output includes `published_date`; SBOM metadata includes image creation timestamp) and would capture risk signals that pure CVE counts miss.

**First-party pipeline extension.** The current scope evaluates pre-built third-party images where source code is unavailable. A natural and high-value extension is a first-party build mode where Semgrep SAST runs against developer source code at build time, unlocking application-layer features (`semgrep_total`, `semgrep_high_count`) that the feature vector already anticipates. This would cover a distinct and complementary risk surface: coding defects introduced before any binary is produced.

**Automated model lifecycle management.** A lightweight distribution drift detector—comparing incoming feature vectors against the training distribution using Mahalanobis distance or an isolation forest—would flag out-of-distribution predictions without requiring ground-truth labels, providing an early warning signal for when retraining is warranted.

**Probability calibration.** Wrapping the Decision Tree in a calibration layer (Platt scaling or `CalibratedClassifierCV`) would produce well-grounded confidence scores, allowing the WARN→BLOCK escalation threshold to be derived empirically from a calibration curve rather than set conservatively by convention.

---

## Summary

This project demonstrates that supply chain risk decisions do not have to be binary or opaque. By grounding deployment gates in structured, interpretable feature vectors derived from open scanning tools, and by embedding human authority and full audit trails into the pipeline architecture, the system offers a practical and governable alternative to the current state of either over-blocking or under-enforcing. The feature vector framing is not specific to container images—any software artifact with a scannable SBOM can be evaluated by the same pipeline, making the contribution extensible to a broad class of supply chain risk problems.
