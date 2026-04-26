# Project Brief: Risk-Aware ML-Gated Supply Chain Security

## Problem

Software supply chain attacks have become a dominant threat vector. Attackers increasingly compromise widely-used container images, libraries, and build artifacts rather than targeting end-user systems directly. The 2021 SolarWinds and Log4Shell incidents demonstrated that a single vulnerable dependency can cascade across thousands of downstream deployments within hours.

CI/CD pipelines are the last automated gate before code reaches production, yet most existing pipelines fail at supply chain risk in two ways. First, binary enforcement without nuance: vulnerability scanners return raw CVE lists, and pipelines either fail on *any* critical finding—generating false-positive noise that erodes developer trust—or pass everything through with no meaningful security gate. Second, no audit trail or governance layer: even when scans run, the decision logic—which vulnerabilities matter, why the build was allowed, who approved an exception—is often absent, making compliance attestation impossible.

The gap is not in scanning capability; mature open tools exist. The gap is in the **risk translation layer**: converting structured vulnerability data into an explainable, auditable, policy-consistent deployment decision.

---

## Motivation

Solving this problem has direct policy backing. Executive Order 14028 (May 2021) mandated Software Bills of Materials for all software procured by the federal government, establishing SBOMs as a compliance artifact rather than an optional best practice. This creates a concrete, regulatory-grounded rationale for building systems that consume and reason over SBOM data.

The architectural choice to center the system on SBOMs rather than raw scanner output is deliberate. A raw vulnerability scanner produces a point-in-time list of findings. An SBOM is a persistent, queryable artifact: when a new CVE is published after a build, existing SBOMs can be queried retroactively without re-scanning the image. More importantly for this system, an SBOM is structured data—it can be parsed, feature-extracted, and fed into a classifier. A raw scanner report cannot.

Each tool was chosen to address a specific constraint. CycloneDX is the OWASP-governed SBOM standard designed specifically for security use cases, in contrast to SPDX which is optimized for license compliance. Its JSON encoding allows direct programmatic extraction with standard libraries, and it unifies component inventory and vulnerability data in a single document. Trivy produces both the SBOM and the vulnerability scan in a single pass, eliminating pipeline complexity and any mismatch between what was inventoried and what was scanned; it outputs CycloneDX natively without a conversion step. GitHub Actions is where build decisions already happen—security analysis inserted at the CI/CD layer runs at the exact moment an artifact is promoted, without requiring a separate platform or developer behavior change.

A machine learning classifier rather than purely a static ruleset addresses the central limitation of threshold-based systems: rules do not adapt. As the vulnerability landscape evolves, manually maintained cutoffs drift out of calibration with real-world risk. A classifier trained on labeled examples generalizes across the interaction of features—an image with a moderate CVE count but unusually dangerous weakness types can be flagged even if no single threshold is breached. A Decision Tree specifically was chosen because every BLOCK decision must be explainable to the developer appealing it and to the auditor reviewing the log. A model that cannot be read is a model that cannot be trusted.

---

## Approach

This project implements a four-stage ML pipeline that acts as that translation layer.

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

The 8 features cover orthogonal axes of risk: vulnerability volume, severity ceiling, severity distribution, attack surface, weakness breadth, and exploitation likelihood. Severity ratings use the highest rating across all sources per vulnerability—not NVD-only. CWE membership is checked against the MITRE Top 25 (2025) list.

**Stage 3 — Label.** Rule-based thresholds derived from statistical analysis of 371 labeled container images assign each image to ALLOW, WARN, or BLOCK. Labels are frozen in version-controlled CSVs so threshold changes produce a visible `git diff` rather than a silent accuracy drop—applying the supply chain integrity principle to the model's own training data. Training dataset: 172 well-maintained images (ALLOW), 154 aged/stale images (WARN), 45 known-vulnerable images (BLOCK).

**Stage 4 — Classify.** A Decision Tree trained on those labeled CSVs produces the final risk decision with a confidence score. A confidence-based escalation policy promotes uncertain WARN predictions (confidence < 0.75) to BLOCK, embedding cost asymmetry directly into the inference path rather than relying solely on training weights. Human reviewers retain override authority; all decisions, confidence scores, and overrides are logged for audit.

---

## Results

Model development has proceeded iteratively, with each version addressing a specific weakness identified in the previous round. Detailed metrics and artifacts are preserved in `ml-classifier/model-results/`.

The initial prototype established that the pipeline was feasible—the classifier could separate ALLOW from BLOCK reliably—but exposed the WARN class as the persistent weak point. Model v0.0.1 introduced structured hyperparameters and added image age as a temporal feature; WARN performance improved substantially, but high cross-validation variance signaled that 143 training images were not enough to produce a stable model. Model v0.0.2 addressed that directly with a dataset expansion from 143 to 371 images; CV variance dropped significantly, confirming the instability had been a data quantity problem rather than a modeling one.

Two conceptual shifts defined the later iterations. Model v0.0.3 removed image age from the feature vector: although it was a strong predictor, it was strong for the wrong reason—the WARN bucket had been built from images in a specific age range, so the model was learning dataset construction logic rather than generalizable risk signal. Class weighting was also changed from balanced to asymmetric, explicitly encoding that a missed threat carries a higher cost than a false alarm. Model v0.0.4 *(current)* embedded that cost asymmetry into the inference path via confidence-based escalation, producing the cleanest tree structure to date.

The classifier reached 97.33% test accuracy and 96.96% ± 1.97% across 5-fold cross-validation. The WARN class—the hardest to separate—reached perfect classification on the test set.

---

## Next Steps

The current system establishes a working, interpretable pipeline and proves the viability of ML-gated deployment decisions. Several high-value extensions would substantially strengthen both the scientific contribution and practical coverage.

The most impactful near-term improvement is stronger training data. Replacing rule-derived labels with labels grounded in real deployment outcomes—post-deployment incidents, security team escalations, red-team findings—would allow the model to learn independent risk signal rather than approximate its own training rules. Expanding the BLOCK class beyond its current 45 images using public vulnerability databases (OSV, NVD advisories, VulnDB) would also reduce sensitivity to distributional shift when new vulnerability patterns emerge.

Richer features represent a natural second priority. Temporal signals—days-since-rebuild, days-since-vulnerability-published—are extractable from existing Trivy output and would capture risk that pure CVE counts miss. A first-party build mode, where SAST runs against developer source code at build time, would unlock application-layer features that the feature vector already anticipates, covering a complementary risk surface to the third-party image evaluation the current system performs.

At the operational level, a lightweight distribution drift detector would flag out-of-distribution predictions without requiring ground-truth labels, providing an early warning signal for when retraining is warranted. Probability calibration would produce well-grounded confidence scores, allowing the WARN→BLOCK escalation threshold to be derived empirically from a calibration curve rather than set conservatively by convention.

---

## Summary

This project demonstrates that supply chain risk decisions do not have to be binary or opaque. By grounding deployment gates in structured, interpretable feature vectors derived from open scanning tools, and by embedding human authority and full audit trails into the pipeline architecture, the system offers a practical and governable alternative to the current state of either over-blocking or under-enforcing. The feature vector framing is not specific to container images—any software artifact with a scannable SBOM can be evaluated by the same pipeline, making the contribution extensible to a broad class of supply chain risk problems.
