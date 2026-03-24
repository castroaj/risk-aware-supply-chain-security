# Software Requirements Specification (SRS)
## Risk-Aware Compliance-as-Code CI/CD Pipeline  
**CYSE 690 Capstone — Spring 2026**

**Status:** Under Active Development

**Last Updated:** Mar 2026  

---

## Document Purpose

This document defines the Software Requirements Specification (SRS) for the Risk-Aware Compliance-as-Code CI/CD Pipeline.

**Risk-Aware Compliance-as-Code: An ML-Gated Secure CI/CD Pipeline for Software Supply Chain Integrity.**

The purpose of this document is to:

- Define the system scope and operational boundaries  
- Establish functional and non-functional requirements  
- Specify ML governance and enforcement behavior  
- Define compliance and audit expectations aligned with EO 14028  
- Provide a structured foundation for ongoing architectural refinement

---

## Document Ownership

This SRS is a collaborative baseline document.  
Responsibilities for expansion are scoped as follows:

- **Joseph (Security & Compliance Lead):**
  - Compliance requirements (EO 14028 alignment)
  - Audit logging and evidence retention expectations
  - Security governance considerations

- **Alex (System Architecture & Integration Lead):**
  - CI/CD workflow architecture
  - Tool integration requirements
  - Deployment enforcement design

- **Ayra (ML & Risk Classification Lead):**
  - ML gate logic requirements
  - Feature schema and model decision constraints

- **Derrick (Documentation & Presentation Lead):**
  - Final formatting, diagrams, and report packaging

---

# 1. Project Overview

## Project Assumptions

- Open-source sample projects will be used to generate training data.
- SBOM outputs (CycloneDX), Trivy scan results, and Semgrep results will be available in structured JSON format.
- A labeled dataset will be created internally using a defined severity rubric.
- The ML model will initially be trained offline and deployed in inference-only mode in CI/CD.
- Manual overrides will be permitted for governance purposes.
- The CI/CD environment will execute within GitHub Actions.
- Build artifacts and logs will be stored in a controlled repository or artifact storage.
- The prototype will operate in a controlled academic environment, not a production enterprise system.


## 1.1 System Vision

The goal of this project is to design and implement a secure CI/CD pipeline that integrates:

- SBOM generation  
- Security scanning (SAST + vulnerability analysis)  
- Machine Learning risk classification  
- Automated enforcement decisions  

Instead of a rigid pass/fail model, builds will be classified as:

- **ALLOW**
- **WARN**
- **BLOCK**

based on contextual deployment risk.

---

## 1.2 Scope

This prototype focuses on secure build-time risk assessment within CI/CD.
The system evaluates deployment risk prior to production release but does not
provide continuous runtime monitoring.

1. Builds application artifacts  
2. Generates SBOM evidence  
3. Runs security analysis tools  
4. Normalizes scan outputs into a unified schema  
5. Applies ML-based risk gating  
6. Enforces deployment decisions  
7. Produces audit-ready logs for compliance  

---

## 1.3 Out of Scope

The following are not required in the initial prototype:

- Full enterprise-scale deployment  
- Complete SOC/SIEM production integration  
- Advanced DAST against complex environments  
- Formal compliance certification
- Real-time production runtime threat detection
- Automatic remediation or patching of detected vulnerabilities

---

## 1.4 CI/CD Architecture Overview

Figure 1 illustrates the high-level CI/CD workflow for the
Risk-Aware Compliance-as-Code pipeline.

The workflow consists of:

1. Ingestion and Build
2. Analysis and Risk Assessment
3. Risk-Based Decision
4. Enforcement and Deployment
5. Artifact Retention and Immutable Audit Logging

![Figure 1 – High-Level CI/CD Risk-Aware Workflow](../design/high-level-design.drawio.png)

---

## 1.5 System Context

The system operates within a CI/CD workflow where developers submit code changes.
Upon commit or pull request, the pipeline executes build, scan, ML classification,
and enforcement logic prior to deployment.

The system does not replace existing CI/CD tooling but augments it with
risk-aware decision controls.

---

## 1.6 ML Architecture and Governance Overview

Figure 2 illustrates the internal ML-based risk classification
architecture, including feature engineering, model inference,
policy controls, and manual override mechanisms.

The architecture includes:

- Evidence collection (SBOM, Trivy, Semgrep)
- Feature extraction and normalization
- Version-controlled ML model inference
- Risk-based decision engine
- Artifact retention and audit logging
- Human override and retraining feedback loop

![Figure 2 – ML-Gated Risk Classification Architecture](../design/ml-architecture.drawio.png)

---

# 2. Stakeholders

| Stakeholder | Role |
|------------|------|
| Developers | Submit code and receive security feedback |
| Security & Compliance Lead | Defines governance, audit controls, compliance mapping |
| CI/CD Operator | Maintains pipeline workflow execution |
| Compliance Auditor | Reviews retained logs and evidence |
| Project Team | Implements and validates prototype |

---

# 3. Functional Requirements

## FR-1 SBOM Generation
The system shall generate an SBOM for every build artifact using an automated tool (e.g., Trivy).

---

## FR-2 SBOM Minimum Data Fields

The generated SBOM shall include, at minimum:

- Supplier name 
- Component name 
- Component version 
- Unique identifiers (e.g., CPE, PURL)
- Dependency relationships (including transitive dependencies)
- Author of SBOM data 
- Timestamp of SBOM generation

---

## FR-3 SBOM Operational Requirements

- A new SBOM shall be generated for every build or dependency change.
- The SBOM shall be produced in a machine-readable format (CycloneDX or SPDX).

---

## FR-4 Static Application Security Testing (SAST)
The system shall run static security scanning (e.g., Bandit) on source code and produce structured findings.

---

## FR-5 Vulnerability and Dependency Scanning
The system shall scan dependencies and container artifacts for known vulnerabilities.

---

## FR-6 Unified Output Schema
The system shall normalize outputs from SBOM and scanning tools into a unified schema for ML ingestion.

---

## FR-7 ML Risk Classification Gate
The system shall classify builds into one of the following outcomes:

- ALLOW  
- WARN  
- BLOCK  

based on contextual risk signals.

The ML classifier shall:
- Output a classification label (ALLOW/WARN/BLOCK).
- Log the input feature vector used for classification.
- Support traceability of feature contributions used in classification for audit review.

### Implementation Note (Initial Phase)

The system shall initially use a rule-based classification mechanism to support
early-stage decision enforcement and training data generation.

This rule-based approach applies predefined thresholds on extracted security
features to classify builds into ALLOW, WARN, or BLOCK categories.

In later phases, this mechanism will be replaced or augmented by a machine
learning-based classifier trained on labeled build data.

---

## FR-8 Deployment Enforcement

The system shall enforce deployment decisions based on ML classification outcomes.

- If classification = BLOCK:
  - The system shall prevent artifact promotion to protected branches or production environments.
  - The build shall fail or be marked as non-deployable.

- If classification = WARN:
  - The system shall allow promotion only to a staging environment.
  - Manual review shall be required before production deployment.

- If classification = ALLOW:
  - The system shall permit artifact promotion to production environments.

All enforcement outcomes shall be logged in the audit record.

---

## FR-9 Manual Override Capability

The system shall support manual override for WARN and BLOCK outcomes.

Override actions must:

- Record reviewer identity. 
- Record justification for override. 
- Be stored in the audit log. 
- Be restricted to authorized reviewers.

---

## FR-10 Compliance Logging
The system shall retain, per build execution:

- Scan outputs 
- SBOM artifacts 
- ML classification decisions 
- Enforcement actions 
- Extracted feature vector 
- Manual override records (if applicable)
- Timestamped enforcement decision

All retained artifacts must support audit traceability.

---

## FR-11 Feature Extraction and Normalization

The system shall extract security-relevant statistics from SBOM, vulnerability,
and SAST outputs and normalize them into a fixed feature vector schema
for ML classification.

### Feature Vector Definition (Initial)

The system shall extract the following features (initial set):

- total_dependency_count
- vuln_total
- critical_cve_count
- high_cve_count
- cvss_ge_7_count
- max_cvss
- unique_cwe_count
- top25_cwe_count
- semgrep_total (optional)
- semgrep_high_count (optional)
- base_image_age_days

Notes:
- Semgrep-derived features are marked optional. See `research/semgrep/semgrep_feature_analysis.md` (or `semgrep_feature_analysis.md`) for the project's semgrep feature analysis and rationale for excluding semgrep features from the default feature vector in early experiments. Semgrep features may be enabled as an opt-in augmentation if desired.

### Training Data Labeling

The system shall use a rule-based threshold mechanism to generate initial labels (ALLOW, WARN, BLOCK) for training data generation. This deterministic, rule-based labeling strategy will be used to:

- Produce labeled examples for initial model training.
- Provide a transparent, explainable baseline for enforcement during early development.
- Capture the labeling rules and thresholds in version-controlled configuration so they are auditable and adjustable over time.

The labeling mechanism shall be configurable, and the project team will document the rule set used to generate labels. Example (illustrative) rules that may be used when labeling training data include:

- BLOCK: when critical_cve_count >= 1 OR max_cvss >= 9.0
- WARN: when cvss_ge_7_count > 0 OR high_cve_count > 0 (but does not meet BLOCK criteria)
- ALLOW: when none of the WARN or BLOCK criteria are met

These example thresholds are illustrative; the actual rule set and numeric thresholds used to generate training labels must be recorded in the project's training-data generation documentation and version control.

---

## FR-12 Compliance – SBOM Transparency

The system shall generate machine-readable SBOMs for each build in alignment with EO 14028 requirements.

---

## FR-13 Compliance – Secure Build Practices

The system shall enforce vulnerability scanning and risk-based gating prior to deployment.

---

## FR-14 SBOM Dependency Completeness

The SBOM shall explicitly distinguish between components with no dependencies and components with unknown or incomplete dependency information.

---

## FR-15 SBOM Integrity Verification

The system shall include cryptographic hashes for SBOM-listed components to support verification of exact component versions used in the build.

---


# 4. Non-Functional Requirements

## NFR-1 Decision Latency

The total risk decision time (scan + inference + enforcement) must be measurable and should not introduce unreasonable delay relative to total build time.

---

## NFR-2 Auditability and Traceability
All pipeline decisions must be traceable to:

- Tool outputs  
- Model inputs  
- Enforcement outcomes  

---

## NFR-3 Model Governance

- The ML model shall be version-controlled. 
- The model shall operate in inference-only mode within CI/CD. 
- The system shall log the model version used per build.

---

## NFR-4 Model Transparency

ML-based decisions must be explainable and auditable.
The decision logic must be interpretable (e.g., decision tree or rule-based explanation).
Opaque black-box models are not permitted in the prototype.

---

## NFR-5 Artifact Integrity

All retained artifacts must be protected against tampering.
Artifact storage must ensure integrity verification and controlled access.
Integrity verification mechanisms (e.g., checksums or hash validation)
must be used to ensure artifact immutability.

---

## NFR-6 Reproducibility

Given identical inputs (scan outputs and feature vector),
the ML inference process must produce consistent classification results.

---

## NFR-7 Compliance – Audit Evidence

All compliance-relevant artifacts must be retained in immutable form to support audit review.

---

## NFR-8 Compliance – Decision Traceability

ML-based decisions must remain explainable and traceable for governance validation.

---

## NFR-9 Explainability

The system shall provide explainable classification outputs.

For each classification decision, the system should be able to identify:

- Which features contributed to the decision  
- Which thresholds or conditions were triggered  

This is required to support auditability and compliance validation.

This SRS is a living project document and will be continuously updated throughout
Phases 1–5 of the capstone.

The initial draft establishes:

- Baseline functional and non-functional requirements  
- Compliance alignment with Executive Order 14028  
- Audit logging and evidence retention expectations  

All future refinements (architecture details, ML schema, enforcement workflows,
and expanded compliance controls) will be introduced through pull requests and
tracked via Git version history.

---

## 6. Planned Future Additions

The following sections will be expanded incrementally as the system matures:

- Tool-specific schema definitions for scan output normalization  
- ML feature mapping and risk classification explainability  
- Detailed use cases for ALLOW/WARN/BLOCK decision outcomes  
- Expanded compliance controls, KPIs, and governance workflows  
- Architecture diagrams and CI/CD enforcement integration details  

---

**End of Current Draft — Under Active Development**
