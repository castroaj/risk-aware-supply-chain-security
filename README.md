# Risk-Aware Compliance-as-Code: An ML-Gated Secure CI/CD Pipeline for Software Supply Chain Integrity

## Documentation

- [System Architecture](./documentation/architecture/) - High-level system architecture and component design
- [Design](./documentation/design/) - Includes diagrams or documentation detailing the architecture of the pipeline
- [Meetings](./documentation/meetings/) -  Meeting notes as made by the team
- [Project Plan](./documentation/project-plan/) - Project plan document, covering what the project aims to cover and how it plans to do so
- [SRS Document](./documentation/srs/) - Official documentation for the project including scope, design, and requirements

## Research

[Software Bill of Materials (SBOM)](./research/sbom/README.md)
- Research into SBOM generation, management, and standards (NTIA) for Python and Docker environments
- Includes the following research:
  - Requirements for SBOM in a secure supply chain
  - SBOM generation techniques
  - Industry standard output formats
  - Tools that will fulfill the needs for the project
  - Options within the Github Actions platform

[SAST](./research/SAST/SAST_Overview.md)
- This is to give overview of the role of Static Application Security Testing (SAST) in improving software security within modern CI/CD pipelines and software supply-chain environments. 
- It provides an overview of how SAST tools detect vulnerabilities early in the development lifecycle and how they are integrated with complementary technologies such as Software Bills of Materials (SBOM) generation, dependency vulnerability scanning, and compliance reporting.

[Dynamic Scanning](./research/dynamic_scanning/Dynamic_Scanning.md)
- This is to give an overview on different dynamic scanning tools or techniques to improve the software security within our pipeline

[ML Model](./research/ML_model/)
- Includes documents relating to the risk-aware classification process based upon SBOM, vulnerability scanning, and SAST results
- Key Documents:
  - [nist-ssdf-research](./research/ML_model/nist-ssdf-research.md)
  - [Classification Proposal](./research/ML_model/classification-proposal.md)
  - [Feature Extraction](./research/ML_model/feature-extraction.md)
  - [Training Data Generation Plan](./research/ML_model/training-data-generation-plan.md)

## ML Classifier

The `ml-classifier/` directory contains the active implementation of the pipeline's risk classification stage. See [`ml-classifier/CLAUDE.md`](./ml-classifier/CLAUDE.md) for full setup and usage instructions.

### What it does

- Scans container images with Trivy to produce CycloneDX JSON SBOMs
- Extracts a 9-feature vector from each SBOM: vulnerability counts (total, critical, high), CVSS scores, CWE coverage (unique and MITRE Top 25), and base image age
- Applies a rule-based threshold classifier to assign a preliminary ALLOW / WARN / BLOCK label to each image
- Trains a Decision Tree classifier on three labelled data buckets (high-quality, aged/stale, known-vulnerable)
- Issues ALLOW / WARN / BLOCK predictions with confidence scores for new SBOM inputs
- Emits structured INFO/DEBUG logs to stdout (and optionally a file) so every classification decision is auditable

### Three CLI entry points

The toolkit ships as a single wheel with three purpose-built commands:

| Command | User | Purpose |
|---|---|---|
| `risk-classifier-label` | Data scientist / pipeline operator | Extract features from SBOM scan data and assign rule-based labels; writes one `<bucket>-labels.csv` per bucket. Run once after scanning to freeze reproducible labels. |
| `risk-classifier-train` | Data scientist / model developer | Train the Decision Tree from pre-labeled CSVs; writes pkl artifacts, a classification report, and visualizations to a timestamped output directory |
| `risk-classifier-predict` | CI/CD pipeline / security engineer | Load saved model artifacts and classify one or more SBOM files; outputs JSON or CSV |

```bash
# Quick start
cd ml-classifier
make install && source .venv/bin/activate

# Step 1 — freeze rule labels from scan data (run once after scanning)
risk-classifier-label \
    --manifests-dir data/image-lists/ \
    --data-root data/scans/ \
    --output-dir data/labels/

# Step 2 — train the Decision Tree from frozen labels
risk-classifier-train \
    --labels-dir data/labels/ \
    --output-dir training-runs/

# Step 3 — predict (CI/CD or ad-hoc)
risk-classifier-predict \
    --sbom path/to/image.json \
    --artifact-dir training-runs/<YYYYMMDD-HHMMSS>/ \
    --format json
```

All three commands accept `--log-level {DEBUG,INFO,WARNING,ERROR}` and `--log-file FILE` for audit logging.

### Current model — v0.1.0

Trained on 143 container images across three label buckets (ALLOW=35, BLOCK=61, WARN=47).

| Metric | Value |
|---|---|
| Dataset | 143 images (train=114 / test=29) |
| Test accuracy | 96.55% |
| CV accuracy | 92.32% ± 5.63% (5-fold stratified) |
| ALLOW F1 | 1.00 |
| WARN F1 | 0.95 |
| BLOCK F1 | 0.96 |

Hyperparameters: `max_depth=5`, `min_samples_split=4`, `min_samples_leaf=2`, `class_weight=balanced`, `random_state=42`.

Model artifacts and the full classification report are in [`ml-classifier/model-results/model-0.0.1/`](./ml-classifier/model-results/model-0.0.1/). Subsequent training runs are written to timestamped subdirectories under `ml-classifier/training-runs/`.

### Feature vector (9 features)

All features are extracted from CycloneDX JSON produced by `trivy image --format cyclonedx`.

| Feature | Description |
|---|---|
| `total_dependency_count` | Total number of components in the SBOM |
| `vuln_total` | Total vulnerability count |
| `critical_cve_count` | Count of critical-severity CVEs |
| `high_cve_count` | Count of high-severity CVEs |
| `cvss_ge_7_count` | Count of vulnerabilities with CVSS ≥ 7.0 |
| `max_cvss` | Highest single CVSS score |
| `unique_cwe_count` | Number of distinct CWE identifiers |
| `top25_cwe_count` | Count of vulnerabilities matching a MITRE Top 25 CWE (2025) |
| `base_image_age_days` | Days since the base image was built (Tier 1: SBOM metadata; Tier 2: Docker Hub API) |

## Software Prototype

TODO

## High Level Design

![High Level Design](./documentation/design/high-level-design.drawio.png)

> Details the high-level design for the CI/CD pipeline

## ML Classification Architecture

![ML Classification Architecture](./documentation/design/ml-architecture.drawio.png)

> Details the design for the ML-Classification architecture
