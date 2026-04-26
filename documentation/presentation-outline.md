# Presentation Outline

## Problem

### The Threat Has Shifted
- Software supply chain attacks target shared dependencies, not end systems directly.
- A single compromised image or library can cascade across thousands of downstream deployments within hours.

### Pipelines Are Not Equipped
- CI/CD is the last automated gate before production — yet most pipelines fail at supply chain risk.
- Scanners return raw CVE lists; pipelines either block on any critical finding or pass everything through.

### The Missing Layer
- Neither approach produces an audit trail: who decided, why, and on what basis?
- The gap is not in scanning capability — it is in the risk translation layer.

---

## Motivation

### Compliance Creates the Opening
- EO 14028 (2021) mandated SBOMs for all federally procured software.
- SBOM consumption is now a compliance requirement, not an optional best practice.
- The regulatory pressure gives this system a concrete, policy-grounded reason to exist.

### SBOMs Are the Right Artifact
- A raw scanner gives a point-in-time list; an SBOM is a persistent, queryable artifact.
- New CVEs can be evaluated against existing SBOMs without re-scanning the image.
- Structured JSON is parseable, feature-extractable, and directly classifiable — a scanner report is not.

### These Tools for These Reasons
- CycloneDX is purpose-built for security use cases, unifying component inventory and vulnerability data in one document.
- Trivy eliminates pipeline complexity by producing both the SBOM and vulnerability scan in a single pass.
- GitHub Actions is where build promotion already happens — the gate inserts at the right moment with no platform change.

### Why a Decision Tree
- Static thresholds drift; a classifier learns across feature interactions, not individual cutoffs.
- Every BLOCK decision must be readable by the developer appealing it and the auditor reviewing the log.
- A model that cannot be read is a model that cannot be trusted.

---

## Approach

### The Four-Stage Pipeline
- Stage 1 — Scan: Trivy scans container images and produces a CycloneDX SBOM as the canonical artifact.
- Stage 2 — Extract: A feature extractor parses the SBOM JSON into a fixed 8-feature vector.
- Stage 3 — Label: Rule-based thresholds assign ALLOW, WARN, or BLOCK; labels are frozen in version-controlled CSVs.
- Stage 4 — Classify: A Decision Tree trained on those CSVs produces the final risk decision with a confidence score.

### Feature Design
- Eight features cover orthogonal axes of risk: vulnerability volume, severity ceiling, severity distribution, attack surface, weakness breadth, and exploitation likelihood.
- Severity ratings take the highest score across all databases per CVE — not NVD-only.
- CWE membership is checked against the MITRE Top 25 (2025) list.

### Labeling Strategy
- Thresholds were derived from statistical analysis of 371 scanned container images across three buckets: ALLOW, WARN, and BLOCK.
- Labels are frozen at scan time so threshold changes produce a visible diff rather than a silent accuracy shift.
- Supply chain integrity applied to the model's own training data.

### Inference and Governance
- WARN predictions below 0.75 confidence are automatically promoted to BLOCK, embedding cost asymmetry directly into inference.
- Human reviewers retain override authority; all decisions, confidence scores, and overrides are logged for audit.

---

## Results

### Model Performance
- The classifier reached 97.33% test accuracy and 96.96% ± 1.97% across 5-fold cross-validation.
- The WARN class — the hardest to separate — reached perfect classification on the test set.

### Getting There: Four Iterations
- The initial prototype confirmed feasibility but exposed WARN as the persistent weak point.
- v0.0.1 added image age as a feature; WARN improved but high CV variance revealed data scarcity.
- v0.0.2 expanded the dataset from 143 to 371 images; CV variance dropped significantly.

### The Key Conceptual Shifts
- v0.0.3 removed image age — a strong predictor, but for the wrong reason: the model was learning dataset construction logic, not risk signal.
- v0.0.3 also introduced asymmetric class weights, explicitly encoding that a missed threat costs more than a false alarm.
- v0.0.4 embedded that cost asymmetry into inference via confidence-based escalation, producing the cleanest tree structure to date.

---

## Next Steps

### Stronger Training Data
- Replace rule-derived labels with operational ground truth from real deployment outcomes and security team escalations.
- Expand the BLOCK class beyond 45 images using OSV, NVD, and VulnDB to source historically vulnerable image:tag pairs.

### Richer Features
- Add temporal features — days-since-rebuild, days-since-CVE-published — extractable from existing Trivy output.
- Integrate SAST at build time to unlock application-layer features already anticipated in the feature vector.

### Operational Maturity
- Add a distribution drift detector to flag out-of-distribution predictions without requiring ground-truth labels.
- Apply probability calibration so the WARN→BLOCK threshold is derived empirically rather than set by convention.
