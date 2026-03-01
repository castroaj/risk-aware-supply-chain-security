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

## FR-2 Static Application Security Testing (SAST)
The system shall run static security scanning (e.g., Bandit) on source code and produce structured findings.

---

## FR-3 Vulnerability and Dependency Scanning
The system shall scan dependencies and container artifacts for known vulnerabilities.

---

## FR-4 Unified Output Schema
The system shall normalize outputs from SBOM and scanning tools into a unified schema for ML ingestion.

---

## FR-5 ML Risk Classification Gate
The system shall classify builds into one of the following outcomes:

- ALLOW  
- WARN  
- BLOCK  

based on contextual risk signals.

The ML classifier shall:
- Output a classification label (ALLOW/WARN/BLOCK).
- Output a confidence or probability score.
- Log the input feature vector used for classification.
- Support traceability of feature contributions used in classification for audit review.

---

## FR-6 Deployment Enforcement

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

## FR-7 Compliance Logging
The system shall retain, per build execution:

- Scan outputs  
- SBOM artifacts  
- ML classification decisions  
- Enforcement actions
- Extracted feature vector
- ML confidence score
- Manual override records (if applicable)
- User identity associated with override
- Timestamped enforcement decision

to support compliance evidence and audit review.

---

## FR-8 Feature Extraction and Normalization

The system shall extract security-relevant statistics from SBOM, vulnerability,
and SAST outputs and normalize them into a fixed feature vector schema
for ML classification.

---

# 4. ML Governance and Override Requirements

## 4.1 Model Governance

The ML classifier shall:

- Be version-controlled.
- Operate in inference-only mode within CI/CD.
- Log model version used per build.
- Support offline retraining using labeled datasets.

## 4.2 Manual Override Policy

The system shall support manual override for WARN and BLOCK outcomes.

Override actions must:

- Record reviewer identity.
- Record justification for override.
- Be stored in the audit log.
- Be incorporated into future retraining dataset evaluation.
- Override capability shall be restricted to authorized reviewers.

## 4.3 Explainability Requirement

The system shall retain sufficient feature-level data to allow post-deployment audit of:

- Why a decision was made.
- Which features contributed to classification.

## 4.4 Severity Assessment Rationale

Risk classification is influenced by measurable security indicators including:

- Critical vulnerability counts
- Maximum CVSS score
- Presence of fix-available vulnerabilities
- High-severity SAST findings in sensitive categories

These features are selected based on their direct relationship to exploitability,
impact, and deployment risk.

The model must use only features with documented security relevance.

# 5. Non-Functional Requirements

## NFR-1 Decision Latency

The total risk decision time (scan + inference + enforcement) must be measurable and should not introduce unreasonable delay relative to total build time.

---

## NFR-2 Auditability and Traceability
All pipeline decisions must be traceable to:

- tool outputs  
- model inputs  
- enforcement outcomes  

---

## NFR-3 Extensibility
The system must support modular substitution of scanning tools or ML models.

---

## NFR-4 Secure Artifact Retention
Logs and artifacts must be stored securely and protected against tampering.

---

## NFR-5 Model Transparency

The system must ensure that ML-based decisions are explainable and auditable.
The decision logic must be interpretable (e.g., decision tree or rule-based explanation),
and opaque black-box models are not permitted in the prototype.

---

## NFR-6 Artifact Integrity

All retained artifacts must be protected against tampering.
Artifact storage must ensure integrity verification and controlled access.
Integrity verification mechanisms (e.g., checksums or hash validation)
must be used to ensure artifact immutability.

---

## NFR-7 Reproducibility

Given identical inputs (scan outputs and feature vector),
the ML inference process must produce consistent classification results.

---


# 6. Compliance Requirements (EO 14028 Alignment)

The system will align with Executive Order 14028 through:

| EO 14028 Objective | Pipeline Control |
|-------------------|------------------|
| SBOM Transparency | Automated SBOM generation per build |
| Supply Chain Integrity | Vulnerability scanning + enforcement gate |
| Secure Build Practices | Hardened GitHub Actions workflow |
| Audit Evidence | Immutable logging + artifact retention |
| Model Governance | Version-controlled ML model with logged decision traceability |


---

## 7. Document Status and Evolution

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

## 8. Planned Future Additions

The following sections will be expanded incrementally as the system matures:

- Tool-specific schema definitions for scan output normalization  
- ML feature mapping and risk classification explainability  
- Detailed use cases for ALLOW/WARN/BLOCK decision outcomes  
- Expanded compliance controls, KPIs, and governance workflows  
- Architecture diagrams and CI/CD enforcement integration details  

---

**End of Current Draft — Under Active Development**

