# Presentation Outline

## Problem

- Software supply chain attacks target shared dependencies, not end systems directly.
- CI/CD pipelines are the last automated gate before production — yet most fail at supply chain risk.
- Scanners return raw CVE lists; pipelines either block on any critical finding or pass everything through.
- Neither approach produces an audit trail: who decided, why, and on what basis?
- The gap is not in scanning capability — it is in the risk translation layer.

## Foundation

- EO 14028 (2021) mandated SBOMs for all federally procured software, making SBOM consumption a compliance requirement.
- SBOMs are structured, persistent artifacts — parseable, feature-extractable, and queryable after the fact.
- CycloneDX unifies component inventory and vulnerability data in a single JSON document designed for security use cases.
- Trivy produces both the SBOM and vulnerability scan in one pass, outputting CycloneDX natively.
- GitHub Actions is where build promotion decisions already happen — inserting the gate here requires no platform change.
- A Decision Tree classifier was chosen because every BLOCK decision must be readable by the developer appealing it and the auditor reviewing it.

## Approach

- Stage 1 — Scan: Trivy scans container images and produces a CycloneDX SBOM as the canonical artifact.
- Stage 2 — Extract: A feature extractor parses the SBOM JSON into a fixed 8-feature vector covering volume, severity, attack surface, and exploitation likelihood.
- Stage 3 — Label: Rule-based thresholds derived from 371 scanned images assign ALLOW, WARN, or BLOCK; labels are frozen in version-controlled CSVs.
- Stage 4 — Classify: A Decision Tree trained on those CSVs produces the final risk decision with a confidence score.
- WARN predictions below 0.75 confidence are automatically promoted to BLOCK, embedding cost asymmetry into the inference path.
- Human reviewers retain override authority; all decisions, scores, and overrides are logged for audit.

## Results

- The classifier reached 97.33% test accuracy and 96.96% ± 1.97% across 5-fold cross-validation.
- Model development ran four iterations, each targeting a specific weakness identified in the previous round.
- v0.0.1 added image age as a feature; WARN performance improved but high CV variance exposed data scarcity.
- v0.0.2 expanded the dataset from 143 to 371 images; CV variance dropped, confirming a data quantity problem.
- v0.0.3 removed image age — a strong predictor, but for the wrong reason — and introduced asymmetric class weights.
- v0.0.4 added confidence-based escalation; the WARN class reached perfect classification on the test set.

## Next Steps

- Replace rule-derived labels with operational ground truth from real deployment outcomes and security team escalations.
- Expand the BLOCK class beyond 45 images using OSV, NVD, and VulnDB to source historically vulnerable image:tag pairs.
- Add temporal features — image age, days-since-rebuild, days-since-CVE-published — extractable from existing Trivy output.
- Integrate Semgrep SAST at build time to add application-layer features already anticipated in the feature vector.
- Add a distribution drift detector to flag out-of-distribution predictions without requiring ground-truth labels.
- Apply probability calibration so the WARN→BLOCK threshold is set empirically rather than by convention.
