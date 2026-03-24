# 1. Prototype Score

### Balancing Complexity with Completeness

# 1.1 Prototype Classification

Type: Research-Oriented Functional Prototype

Maturity Level: Proof-of-Concept (PoC) with operational integration

Primary Goal: Demonstrate feasibility of ML-based risk gating inside CI/CD not enterprise deployment.
________________________________________

# 1.2 Complexity vs. Completeness Evaluation

| Dimension | Level | Justification |
| --------------- | :---------------------: | :------------------: |
| Architectural Complexity  | Moderate–High | Multi-component integration (SAST + SBOM + vuln scanning + ML + CI/CD orchestration) |
| ML Model Complexity | Moderate     | Supervised classification model (e.g., logistic regression / decision tree) with risk scoring |
| Compliance Mapping    | High | EO 14028 + NIST SSDF alignment + control traceability |
| Deployment Complexity | Moderate | Containerized pipeline integration (GitHub Actions / Jenkins / GitLab CI)|
| Enterprise Scale Readiness | Low | Academic infrastructure; not production-hardened|

________________________________________

# 1.3 Prototype Score (Balanced Assessment)

Overall Prototype Score: 8 / 10
Why Not 10?
•	No enterprise deployment validation
•	Limited dataset size
•	No large-scale cloud scaling validation
•	No long-term operational telemetry
Why 8?
•	Full CI/CD automation demonstrated
•	SBOM generation + vulnerability ingestion implemented
•	ML-based risk gating operational
•	Compliance traceability documented
•	Quantitative evaluation of performance and false positives
This represents high functional completeness while maintaining manageable complexity within academic constraints.
________________________________________

# 2. Compliance Constraints

System is constrained by federal secure software supply chain mandates and NIST standards. These are not optional because they shape architecture.
________________________________________

# 2.1 Executive Order 14028

Improving the Nation’s Cybersecurity (May 12, 2021)
Entity Reference: Executive Order 14028
Key Requirements Impacting the Prototype:
•	Mandatory SBOM generation
•	Secure software development practices
•	Vendor attestation of secure SDLC
•	Vulnerability disclosure processes
•	Zero trust alignment
Constraint Implications:
•	SBOM generation must be automated.
•	Pipeline must support vulnerability transparency.
•	ML gating cannot bypass compliance checks.
•	All decisions must be auditable and explainable.
________________________________________

# 2.2 NIST Secure Software Development Framework

Entity Reference: NIST SP 800-218
Relevant Practice Groups:
•	PO (Prepare the Organization)
•	PS (Protect the Software)
•	PW (Produce Well-Secured Software)
•	RV (Respond to Vulnerabilities)
Constraint Impact:
•	SAST must run during development stage.
•	Risk decisions must align with secure coding requirements.
•	ML gating must enhance, not replace, required controls.
•	Traceability must exist between findings and SSDF practices.
________________________________________

# 2.3 NIST Risk Management Framework

Entity Reference: NIST Risk Management Framework
Constraint:
•	Risk scoring must follow structured methodology.
•	ML model must provide explainable risk decisions.
•	Controls must map to security categories.
________________________________________

# 2.4 Additional Relevant Standards

| Standard        | Relevance to Project     | Constraint Impact      |
| --------------- |:---------------------:   | :------------------:|
| NIST SP 800-53  | Security control families| Risk mapping & compliance tagging |
| CycloneDX / SPDX| SBOM schema formats      |  Tool selection limitation |
| CVSS (v3.1)     |Vulnerability severity scoring| Baseline comparison against ML risk score |

________________________________________

Compliance Constraint Summary
The prototype must:
•	Generate machine-readable SBOM
•	Map vulnerabilities to known CVEs
•	Align risk scoring to NIST frameworks
•	Produce auditable outputs
•	Support secure SDLC documentation
•	Avoid black-box decision-making
Failure to meet these invalidates compliance viability.
________________________________________

# 3. Technical Infrastructure Constraints

(Free/Open-Source, No Significant Budget)
This project is intentionally constrained to zero-cost infrastructure to demonstrate feasibility for academic and low-budget environments.
________________________________________

# 3.1 Core CI/CD Environment

|Component	|Open-Source Option
|:---------------------:   | :------------------:|
|Version Control	|Git |
|CI/CD Orchestration |	GitHub Actions (free tier) / GitLab CI |
|Containerization|	Docker| 
|Build Automation|	Make / Maven / npm|
________________________________________

# 3.2 Security & SBOM Tooling

|Function	|Tool|	Cost|
|:---------------------:   | :------------------:|:------------------:|
|SAST	|Semgrep (Community)	|Free|
|Vulnerability Scanning	|Trivy	|Free|
|SBOM Generation	|Trivy / Syft	|Free|
|Dependency Analysis|	OWASP Dependency-Check	|Free|
________________________________________

# 3.3 ML Layer

|Component|	Technology|
|:---------------------:   | :------------------:|
|Programming Language|	Python|
|ML Framework	|scikit-learn|
|Data Processing|	Pandas|
|Visualization	|Matplotlib / Seaborn|

All tools are:
•	Open-source
•	Locally deployable
•	Container-compatible
•	No licensing cost
________________________________________

# 3.4 Infrastructure Limitations

Because no enterprise budget exists:
•	No dedicated cloud cluster
•	No GPU instances
•	No paid threat intelligence feeds
•	No enterprise DevSecOps tooling (e.g., Prisma, Checkmarx Enterprise)
Impact:
•	Model must be lightweight.
•	Dataset must be small.
•	Pipeline must operate on standard laptop or free cloud tier.
•	Performance testing is limited to simulated workloads.
________________________________________

Final Structured Summary
Prototype Score:
8/10 — High functional completeness, moderate complexity, limited enterprise validation
Compliance Constraints:
•	EO 14028 mandates SBOM + secure SDLC.
•	NIST SP 800-218 requires shift-left security integration.
•	Risk decisions must be auditable and explainable.
•	Must align with CVSS + NIST control families.
Technical Infrastructure:
•	100% open-source
•	Zero infrastructure budget
•	Dockerized CI/CD
•	Python-based ML
•	Public vulnerability feeds only

# 4. Methodology: Risk vs. Constraint Traceability

To ensure methodological validity, each identified project constraint is mapped to corresponding implementation risks and mitigation strategies. This traceability matrix demonstrates structured systems engineering alignment.

|Constraint Category	|Specific Constraint|	Associated Risk	|Methodological Impact	|Mitigation Strategy|
|:---------------------:   | :------------------:|:------------------:|:------------------:|:------------------:|
|Technical	|Limited CI/CD simulation environment	|Reduced external validity|	Results may not fully generalize to enterprise pipelines|	Clearly define test environment assumptions|
|Technical	|Tool output format limitations	|Data parsing inconsistency|	ML model input variability	|Standardize JSON/SARIF normalization layer|
|Data|	Public vulnerability feeds only|	Incomplete threat coverage|	Model may miss zero-day or proprietary intelligence	|State dataset limitations; focus on known CVEs|
|Time|	Semester-based timeline|	Limited model tuning|	Reduced optimization depth|	Use baseline + incremental improvement evaluation|
|Computational|	No dedicated GPU|	Slower training time|	Smaller training dataset|	Use lightweight ML algorithms (e.g., logistic regression, decision trees)|
|Regulatory|	EO 14028 compliance alignment	|Over-constraining design flexibility|	Reduced architectural freedom	|Integrate compliance mapping early in design|
|Performance	|Build-time latency threshold|	Developer resistance|	Reduced DevSecOps adoption feasibility|	Measure runtime overhead quantitatively|
|Security|	Model explainability requirement|	ML opacity risk|	Reduced audit trust	|Use interpretable models and feature importance analysis|
|Scope|	Academic proof-of-concept|	Limited scalability validation|	Enterprise applicability constrained	|Clearly define as research prototype|

________________________________________
# 5. Compliance-Aligned ML-Gated Secure CI/CD Architecture
   
This architecture integrates security scanning, SBOM generation, and machine-learning–based risk classification into a CI/CD pipeline. The system ingests vulnerability intelligence, processes security features, and performs explainable ML risk scoring to enforce policy-driven build gating decisions (ALLOW, WARN, BLOCK). Compliance traceability is maintained through immutable audit logs aligned with Executive Order 14028 and NIST Secure Software Development Framework (SP 800-218).

# 5.1 Secure CI/CD pipeline integrated with machine learning for risk inference and compliance gating 

<img width="975" height="532" alt="image" src="https://github.com/user-attachments/assets/7d46fb05-6c8e-4d68-81ab-3e5464c966e8" />

