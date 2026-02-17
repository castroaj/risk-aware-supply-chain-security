# Software Requirements Specification (SRS)
## Risk-Aware Compliance-as-Code CI/CD Pipeline  
**CYSE 690 Capstone — Spring 2026**

**Version:** 0.1 (Phase 1 Skeleton Draft)  
**Last Updated:** Feb 2026  

---

## Document Purpose

This document defines the initial Software Requirements Specification (SRS) for the capstone project:

**Risk-Aware Compliance-as-Code: An ML-Gated Secure CI/CD Pipeline for Software Supply Chain Integrity.**

The purpose of this Phase 1 skeleton is to establish:

- A shared understanding of system scope and objectives  
- Baseline functional and non-functional requirements  
- Compliance and audit expectations aligned with EO 14028  
- A foundation for later Phase 2–5 expansion  

---

## Document Ownership (Phase 1)

This SRS skeleton is a collaborative baseline document.  
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

The system will provide an end-to-end prototype pipeline that:

1. Builds application artifacts  
2. Generates SBOM evidence  
3. Runs security analysis tools  
4. Normalizes scan outputs into a unified schema  
5. Applies ML-based risk gating  
6. Enforces deployment decisions  
7. Produces audit-ready logs for compliance  

---

## 1.3 Out of Scope (Phase 1)

The following are not required in the initial prototype:

- Full enterprise-scale deployment  
- Complete SOC/SIEM production integration  
- Advanced DAST against complex environments  
- Formal compliance certification  

---

## 1.4 CI/CD Architecture Overview (Alex — Phase 2 Expansion)

> Placeholder: Detailed GitHub Actions workflow stages, tool chaining,
artifact handling, and enforcement gate integration will be added in Phase 2.

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

# 3. Functional Requirements (Initial Draft)

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

## FR-5 ML Risk Classification Gate (Ayra — Phase 2 Expansion)
The system shall classify builds into one of the following outcomes:

- ALLOW  
- WARN  
- BLOCK  

based on contextual risk signals.

> Placeholder: Feature mapping, model constraints, and explainability requirements
will be expanded in Phase 2.

---

## FR-6 Deployment Enforcement (Alex — Phase 2 Expansion)
The system shall prevent deployment when classification = BLOCK.

> Placeholder: Enforcement mechanism within GitHub Actions will be detailed
by the Architecture Lead in Phase 2.

---

## FR-7 Compliance Logging (Joseph — Phase 1 Baseline)
The system shall retain logs and artifacts including:

- Scan outputs  
- SBOM artifacts  
- ML classification decisions  
- Enforcement actions  

to support compliance evidence and audit review.

---

# 4. Non-Functional Requirements

## NFR-1 Decision Latency
The total risk decision time (scan + inference + enforcement) must remain a fraction of overall CI/CD runtime.

---

## NFR-2 Auditability and Traceability (Joseph — Compliance Baseline)
All pipeline decisions must be traceable to:

- tool outputs  
- model inputs  
- enforcement outcomes  

---

## NFR-3 Extensibility
The system must support modular substitution of scanning tools or ML models.

---

## NFR-4 Secure Artifact Retention (Joseph — Compliance Baseline)
Logs and artifacts must be stored securely and protected against tampering.

---

# 5. Compliance Requirements (EO 14028 Alignment)

The system will align with Executive Order 14028 through:

| EO 14028 Objective | Pipeline Control |
|-------------------|------------------|
| SBOM Transparency | Automated SBOM generation per build |
| Supply Chain Integrity | Vulnerability scanning + enforcement gate |
| Secure Build Practices | Hardened GitHub Actions workflow |
| Audit Evidence | Immutable logging + artifact retention |

---

# 6. Security & Compliance Lead Notes (Joseph)

Phase 1 compliance priorities:

- Define minimum audit evidence requirements  
- Ensure ML gate decisions are explainable and logged  
- Establish retention expectations for compliance review  
- Ensure WARN/BLOCK outcomes support governance workflows  

Future Phase Expansion:

- Detailed security requirements (NIST mapping)  
- Override and approval workflows  
- Formal compliance evidence reporting  

---

# 7. Phase 1 Completion Criteria

Phase 1 is considered complete when:

- SRS skeleton exists in repo  
- Baseline FR/NFR requirements are agreed upon  
- EO 14028 compliance mapping is documented  
- Logging/audit expectations are defined  

---

# Next Steps (Phase 2)

Planned additions in Phase 2:

- Tool-specific schema definition  
- ML feature mapping  
- Detailed use cases (ALLOW/WARN/BLOCK scenarios)  
- Expanded compliance controls and KPIs  
- Architecture diagrams and workflow enforcement logic  

---

**End of Phase 1 SRS Skeleton Draft**
