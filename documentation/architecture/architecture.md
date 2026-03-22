# System Architecture
## Risk-Aware Compliance-as-Code CI/CD Pipeline

---

## 1. Overview

This document describes the high-level architecture of the Risk-Aware
Compliance-as-Code CI/CD Pipeline.

The system integrates security scanning, SBOM analysis, feature extraction,
and risk-based decision-making to classify builds into:

- ALLOW  
- WARN  
- BLOCK  

The architecture supports both rule-based classification (initial phase)
and future ML-based risk classification.

---

## 2. High-Level Workflow

The CI/CD pipeline consists of the following stages:

1. Code Ingestion and Build  
2. Security Analysis (SBOM + Vulnerability + SAST)  
3. Feature Extraction  
4. Risk Classification  
5. Deployment Enforcement  
6. Artifact Retention and Audit Logging  

---

## 3. System Components

### 3.1 SBOM Generation

- Tool: Trivy  
- Output Format: CycloneDX JSON  

Generates a Software Bill of Materials (SBOM) and vulnerability scan results
for each build artifact.

---

### 3.2 Feature Extraction Engine

- Component: `sbom_extractor.py`

Responsibilities:

- Parse CycloneDX SBOM  
- Extract security-relevant metrics  
- Normalize data into a fixed feature vector  

---

### 3.3 Feature Vector

The extracted feature vector includes:

- Vulnerability metrics (CVE counts, CVSS scores)  
- Dependency metrics  
- CWE-based weakness indicators  
- Static analysis metrics (Semgrep - optional)  
- Supply chain freshness (base image age)  

**Initial Feature Set:**

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

See `research/ML_model/feature-extraction.md` for detailed rationale and extraction methodology.

---

### 3.4 Classification Engine

#### Current (Phase 1 – Rule-Based)

- Rule-based classification using configurable thresholds:
  - BLOCK thresholds  
  - WARN thresholds  
  - ALLOW (default/pass-through)

See `research/ML_model/training-data-generation-plan.md` for the rule-based labeling rubric.

#### Future (Phase 2+ – ML-Based)

- Decision Tree ML model  
- Trained on labeled feature vectors  
- Replaces or augments rule-based classifier

---

### 3.5 Decision Engine

Based on classification:

| Classification | Action |
|---------------|--------|
| ALLOW | Deploy to production |
| WARN | Deploy to staging + manual review |
| BLOCK | Prevent deployment |

---

### 3.6 Artifact Retention

The system retains:

- SBOM outputs  
- Vulnerability scan results  
- Feature vectors  
- Classification decisions  

Purpose:

- Auditability  
- Compliance validation  
- Model retraining and improvement  

---

### 3.7 Audit Logging

Each pipeline execution logs:

- Input artifacts  
- Extracted features  
- Classification result  
- Classification decision justification (features and thresholds triggered)  
- Timestamp  
- Deployment decision and enforcement action  

---

## 4. Data Flow

The system processes data as follows:

```
Code Commit
↓
CI/CD Pipeline Trigger
↓
Build Artifact
↓
Trivy Scan → SBOM + Vulnerabilities
↓
Static Analysis (Semgrep - if enabled)
↓
Feature Extraction (sbom_extractor.py)
↓
Feature Vector
↓
Classification Engine (Rule-Based)
↓
Decision (ALLOW / WARN / BLOCK)
↓
Deployment Enforcement
↓
Artifact Retention + Audit Log
```

---

## 5. Training Data Generation Flow

Separate from CI/CD runtime:

1. Select container images (CSV input)  
2. Run automated Trivy scans  
3. Extract feature vectors  
4. Apply rule-based labeling (programmatic threshold mechanism)  
5. Store labeled dataset for ML training  

See `research/ML_model/training-data-generation-plan.md` for detailed methodology.

---

## 6. Decision Latency

Decision latency is defined as:

**Time taken from completion of security scans to final classification decision.**

This includes:

- Feature extraction time  
- Classification time  

The system aims to minimize latency to avoid delaying CI/CD pipelines.

---

## 7. Compliance Considerations

The architecture supports EO 14028 requirements:

- SBOM generation → Transparency  
- Vulnerability scanning → Supply chain integrity  
- Risk-based enforcement → Secure deployment  
- Artifact retention → Audit readiness  
- Explainability → Governance validation  

All classification decisions are traceable to:
- Extracted features  
- Triggered thresholds  
- Supporting evidence (SBOM, vulnerability scan results)

---

## 8. Future Enhancements

- Replace rule-based classification with trained ML model  
- Expand dataset size and diversity for ML training  
- Add model performance metrics (accuracy, precision, recall)  
- Integrate with enterprise logging/SIEM systems  
- Extend feature vector with additional signal sources  
- Implement continuous model evaluation and retraining pipeline  

---

## 9. Summary

This architecture provides a modular and extensible foundation for
risk-aware CI/CD pipelines.

It enables:

- Security-driven deployment decisions  
- Audit-ready traceability  
- Scalable ML integration  
- Explainable and governed decision-making  

---

**End of Document**

