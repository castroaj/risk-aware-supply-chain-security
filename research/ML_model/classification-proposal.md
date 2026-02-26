# ML Methodology Proposal: Risk-Based Classification Model

Project: Risk-Aware Compliance-as-Code  
Author: Ayra Islam, Alexander Castro  
Date: Feb 22, 2026 (Modified: Feb 26, 2026)  

---

## I. Purpose and Scope

This document proposes the methodology for the Machine Learning (ML) Risk Classification component integrated within the GitHub Actions workflow.

The ML model is positioned as an efficiency-enhancing, decision-support mechanism within the CI/CD pipeline. It does not replace formal risk governance or human review. Instead, it improves consistency and speed in identifying potentially risky builds by aggregating structured security signals prior to deployment.

The classifier produces one of three deployment categories:
- ALLOW
- WARN
- BLOCK
However, final authority remains with designated human reviewers.

---

## II. Architectural Context

Within the GitHub Actions workflow, the ML component resides in the **Analysis & Risk Assessment** phase.

Pipeline Flow:

1. Developer pushes code
2. Build and unit tests execute
3. SBOM generation occurs
4. Vulnerability scanning executes
5. SAST canning executes
6. Unified SBOM, vulnerability, and SAST output is generated
7. ML Risk Classifier consumes structured feature set
8. Risk-Based Decision is produced
9. Enforcement logic applies ALLOW, WARN, or BLOCK
10. All decisions logged to immutable audit log

The ML model operates strictly on structured outputs from prior deterministic tools.

---

## III. Problem Formulation

The classification problem is formulated as a supervised multi-class classification task.

### Input

Structured feature vector derived from:
- SBOM dependency metrics
- Vulnerability severity distribution
- SAST findings
- Build metadata (container)

Example features include:
- SBOM (Trivy)
  - `total_dependency_count`
- Vulnerability Scan (Trivy)
  - `vuln_total`
  - `critical_cve_count`
  - `high_cve_count`
  - `cvss_ge_7_count`
  - `max_cvss`
  - `fix_available_count`
  - `unique_cwe_count`
  - `top25_cwe_count`
- SAST Scan (Semgrep)
  - `semgrep_total`
  - `semgrep_high_count`
- Build Metadata (container)
  - `base_image_age_days`

Each CI/CD run generates one feature vector. These features aim to capture an application's security profile without exploding dimensionality.

### Output

The classifier produces a `class_label` based upon classification:
  - BLOCK 
  - WARN
  - ALLOW

---

## IV. Model Selection Rationale

A Decision Tree classifier is proposed for the following reasons:
1. Structured tabular input space  
2. Limited labeled dataset availability  
3. Interpretability and auditability requirements  
4. Low inference latency requirements in CI/CD  
5. Compliance alignment (transparent decision boundaries)

Tree-based models are well-suited for structured security telemetry and enable explicit inspection of decision splits.

---

## V. Training Data Strategy

Training data will consist of structured build records with manually assigned labels.

### Labeling Approach

Labels are derived from a predefined organizational risk rubric based on:

- Vulnerability severity thresholds
- Dependency exposure ratios
- Presence of critical findings
- Contextual risk factors

This ensures the model reflects organizational risk tolerance rather than redefining it.

### Dataset Composition

Each training sample includes:

- Extracted feature vector
- Expert-assigned deployment classification

Override events will be stored and incorporated into future retraining cycles.

---

## VI. Training Process

The training process will follow these steps:

1. Feature extraction from SBOM and SAST outputs
2. Normalization into unified schema
3. Train-test split
4. Model training using scikit-learn DecisionTreeClassifier
5. Depth limitation to prevent overfitting
6. Cross-validation

Hyperparameters to control:

- max_depth
- min_samples_split
- min_samples_leaf

---

## VII. Evaluation Metrics

Model performance will be evaluated using:

- Confusion Matrix
- Precision and Recall (especially for BLOCK)
- Decision Congruence Rate (ML vs manual review)
- False Override Rate
- Inference latency impact

Emphasis is placed on minimizing false negatives (incorrect ALLOW decisions).

---

## VIII. Human-in-the-Loop Integration

The ML classifier is not autonomous.

Override capability allows human reviewers to:

- Accept or reject model decisions
- Provide justification
- Trigger retraining feedback

All override events are logged.

This preserves governance and aligns with compliance requirements.

---

## IX. Logging and Auditability

For each classification event, the system logs:

- Extracted feature vector used for inference
- Model version identifier
- Class prediction
- Probability distribution
- Final enforcement action
- Override flag (if applicable)
- Timestamp

### Artifact Storage

In addition to structured log entries, the system stores the following build artifacts:

- Generated SBOM file (e.g., CycloneDX or SPDX format)
- Raw vulnerability scan output (JSON)
- Raw SAST scan output
- Unified normalized feature schema (input to ML model)
- ML classification output record (label + probability)

These artifacts are retained as CI/CD build artifacts within controlled storage and linked to the corresponding build identifier.

Artifact retention ensures that:

- Each deployment decision can be reconstructed
- Security reviewers can validate the underlying evidence
- Compliance audits can reference original scan outputs
- Overrides can be justified with traceable documentation

Artifacts are versioned and associated with the immutable audit log entry for that build.

---

## X. Model Lifecycle Management

The ML component includes:

- Version control of model artifacts
- Periodic retraining based on override trends
- Drift monitoring through feature distribution analysis
- KPI tracking over time

Model updates will follow pull request review processes.

---

## XI. Limitations

- Model performance dependent on labeling quality
- Potential overfitting with small dataset
- Vulnerability ecosystem shifts may cause drift
- Adversarial manipulation of structured features

The classifier supports prioritization and efficiency but does not serve as final risk authority.

---

## XII. Classification Example

The below pseudo-code demonstrates a potential classification decisions

```python
if (
    critical_cve_count > MIN_ALLOWABLE_CRITICAL_CVE or \
    max_cvss >= MAX_ALLOWABLE_CVSS or \
    (high_cve_count >= MIN_ALLOWABLE_HIGH_CVE_COUNT and fix_available_count >= MIN_ALLOWABLE_FIX_AVAILABLE_COUNT) or \
    semgrep_high_count > ALLOWABLE_SEMGREP_HIGH_COUNT
    ):
    return "BLOCK"
elif (
    high_cve_count in ALLOWABLE_HIGH_CVE_RANGE or \
    cvss_ge_7_count >= ALLOWABLE_CVSS_GE_7_COUNT or \
    semgrep_total >= ALLOWABLE_SEMGREP_COUNT
   ):
    return "WARN"
else:
    return "ALLOW"
```

---

## XIII. Conclusion

The Decision Tree–based ML classifier provides structured, contextual, and efficient risk aggregation within the CI/CD workflow.

It improves identification and prioritization of potentially risky builds while preserving human oversight and SSDF-aligned governance processes.

The model enhances operational efficiency without redefining formal risk management.