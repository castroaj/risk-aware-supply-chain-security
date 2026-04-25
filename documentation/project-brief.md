# Project Brief: Risk-Aware ML-Gated Supply Chain Security

## Problem

Software supply chain attacks have become a dominant threat vector. Attackers increasingly compromise widely-used container images, libraries, and build artifacts rather than targeting end-user systems directly. The 2021 SolarWinds and Log4Shell incidents demonstrated that a single vulnerable dependency can cascade across thousands of downstream deployments within hours.

CI/CD pipelines are the last automated gate before code reaches production, yet most existing pipelines fail at supply chain risk in two ways:

1. **Binary enforcement without nuance.** Tools like Trivy or Grype return raw vulnerability lists, and pipelines either fail on *any* critical CVE—generating false-positive noise that erodes developer trust—or pass everything through with no meaningful security gate.

2. **No audit trail or governance layer.** Even when scans run, the decision logic—which vulnerabilities matter, why the build was allowed, who approved an exception—is often absent, making compliance attestation impossible.

The gap is not in scanning capability; mature open tools exist. The gap is in the **risk translation layer**: converting structured vulnerability data into an explainable, auditable, policy-consistent deployment decision.

---

## Approach

This project implements a four-stage ML pipeline that acts as that translation layer:

**Stage 1 — Scan.** Trivy scans container images and produces CycloneDX-format SBOMs containing components and vulnerability data. The SBOM is the canonical artifact; everything downstream is derived from it.

**Stage 2 — Extract.** A feature extractor parses the CycloneDX JSON and produces a fixed 8-feature vector: `total_dependency_count`, `vuln_total`, `critical_cve_count`, `high_cve_count`, `cvss_ge_7_count`, `max_cvss`, `unique_cwe_count`, `top25_cwe_count`. Severity ratings take the highest score across all databases per CVE. CWE membership is checked against the MITRE Top 25 (2025) list.

**Stage 3 — Label.** Rule-based thresholds derived from statistical analysis of 371 labeled container images assign each image to ALLOW, WARN, or BLOCK. Labels are frozen in version-controlled CSVs so threshold changes produce visible diffs rather than silent accuracy shifts.

**Stage 4 — Classify.** A Decision Tree trained on those labeled CSVs (97.33% test accuracy, 96.96% ± 1.97% 5-fold CV) produces the final risk decision. A confidence-based escalation policy promotes uncertain WARN predictions (confidence < 0.75) to BLOCK. Human reviewers retain override authority; all decisions, confidence scores, and overrides are logged for audit.

Training dataset: 172 well-maintained images (ALLOW), 154 aged/stale images (WARN), 45 known-vulnerable images (BLOCK).

---

## Value

**Interpretability over accuracy.** Decision Trees produce human-readable split rules. Security engineers can audit exactly which feature values triggered a BLOCK without reverse-engineering a neural network. This is not an academic preference—it is a compliance requirement in regulated industries. An explainable model that auditors can inspect is worth more than a more accurate opaque one.

**Risk translation reduces alert fatigue.** The system does not simply count CVEs; it contextualizes them. A single critical CVE in an otherwise clean image is different from a hundred low-severity CVEs across hundreds of stale dependencies. Translating raw counts into ALLOW/WARN/BLOCK with documented thresholds reduces the noise that causes developers to disable security gates.

**Reproducible governance.** Committing labeled CSVs to Git means every training run can be reproduced, every threshold change is visible in history, and every model version traces back to a specific labeled dataset. This applies the supply chain security principle to the model's own training data.

**Pipeline-native integration.** The classifier is not a standalone tool—it is a CI/CD gate. The design explicitly places a human in the loop with override capability and full audit logging, fitting the actual governance model of most organizations (security team approves; engineers ship) rather than requiring full automation.

**Generalizability of the feature vector.** The 8 features cover orthogonal axes of supply chain risk: vulnerability volume, severity ceiling, severity distribution, attack surface, weakness breadth, and exploitation likelihood. This framing is applicable beyond container images to any software artifact with a scannable SBOM.

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

This project demonstrates that supply chain risk decisions do not have to be binary or opaque. By grounding deployment gates in structured, interpretable feature vectors derived from open scanning tools, and by embedding human authority and full audit trails into the pipeline architecture, the system offers a practical and governable alternative to the current state of either over-blocking or under-enforcing. The extensions above represent a natural research agenda for validating and expanding the contribution.
