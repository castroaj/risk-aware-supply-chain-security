Static Application Security Testing in ML-Gated CI/CD Pipelines:

Enhancing Software Security Through Risk-Aware DevSecOps
________________________________________

1. Abstract
   
Modern software development increasingly relies on automated Continuous Integration and Continuous Deployment (CI/CD) pipelines to accelerate delivery and maintain operational efficiency. However, this rapid development paradigm introduces significant security risks, particularly within the software supply chain. Static Application Security Testing (SAST) has emerged as a foundational security control in DevSecOps environments by enabling early detection of vulnerabilities directly within source code. This paper examines how SAST improves software security in modern CI/CD pipelines and evaluates its effectiveness when integrated into risk-aware, machine-learning-gated deployment architectures. While SAST enhances early vulnerability detection and supports secure development lifecycle practices, its effectiveness depends heavily on configuration accuracy, developer adoption, and integration with complementary tools such as Dynamic Application Security Testing (DAST) and Software Composition Analysis (SCA). The research proposes a model for integrating SAST into ML-assisted risk-based CI/CD pipelines to improve decision-making and reduce false positives while maintaining deployment velocity.

1.1 Introduction

The rapid evolution of DevOps practices has transformed software development into a highly automated and continuous process. CI/CD pipelines enable frequent code integration, automated testing, and rapid deployment. While this approach improves productivity and delivery speed, it also increases the attack surface of software systems. Vulnerabilities introduced early in development can propagate through the pipeline and reach production environments if not detected promptly.
Static Application Security Testing (SAST) plays a crucial role in mitigating these risks by analyzing source code for vulnerabilities before execution. As part of the broader DevSecOps movement, SAST supports “shift-left” security by embedding automated security checks early in the software development lifecycle (SDLC). However, modern pipelines require more than simple vulnerability detection. Organizations must balance security with development velocity, requiring intelligent and risk-aware decision-making mechanisms.
This paper explores how SAST improves software security in CI/CD pipelines and examines its role within ML-gated, risk-aware deployment systems.
________________________________________

2. Background and Literature Review
   
2.1 Static Application Security Testing

SAST analyzes source code, bytecode, or binaries to detect vulnerabilities before runtime. It relies on techniques such as pattern matching, taint analysis, symbolic execution, and data-flow analysis. 
While SAST provides full code coverage and early vulnerability detection, its effectiveness is constrained by incomplete rule sets, limited source-sink specifications, and weak control-flow analysis implementations. 
Studies show that missing vulnerable code patterns account for over 60 % of undetected vulnerabilities, demonstrating that rule-based SAST tools cannot provide comprehensive coverage. 
Combining multiple tools improves detection but increases developer workload due to false positives. 

2.2 Integration with DevSecOps

DevSecOps promotes integrating security throughout the SDLC rather than performing security checks at the end of development. SAST supports this model by enabling continuous security testing within CI/CD pipelines. 
However, static analysis alone cannot evaluate contextual deployment risk, especially in environments with complex dependencies and compliance requirements.
Modern DevSecOps pipelines therefore combine SAST with dynamic testing, software composition analysis (SCA), and runtime monitoring to achieve comprehensive coverage. 

2.3 AI-Enhanced Static Analysis

Recent research explores integrating machine learning and large language models with static analysis. Neuro-symbolic frameworks such as IRIS and LSAST combine deterministic scanning with AI-based contextual reasoning, improving detection rates and enabling whole-repository analysis. 
LLMs demonstrate high vulnerability detection rates but suffer from high false-positive rates. Hybrid approaches that combine static analysis with AI-driven classification show promise for improving both precision and recall. 
These findings motivate the design of a risk-aware pipeline that leverages deterministic scanning outputs while applying machine-learning-based decision logic.
________________________________________

3. System Concept and Architecture

3.1 Vision

The proposed system is a risk-aware compliance-as-code CI/CD pipeline that integrates:
•	SBOM generation
•	SAST scanning
•	Dependency vulnerability analysis
•	ML-based risk classification
•	Automated deployment enforcement
•	Audit-ready logging

The system evaluates each build holistically rather than relying on rigid pass/fail thresholds. Builds are classified as:

•	ALLOW – acceptable risk

•	WARN – requires review

•	BLOCK – unacceptable risk

This approach aligns with modern compliance and supply-chain security requirements. 

3.2 Pipeline Workflow

The pipeline follows these stages:

1.	Code build and artifact creation
2.	SBOM generation for dependency transparency
3.	SAST and vulnerability scanning
4.	Output normalization into a unified schema
5.	ML-based risk classification
6.	Enforcement decision (ALLOW/WARN/BLOCK)
7.	Immutable logging for audit and compliance

The architecture supports modular substitution of tools and models, ensuring extensibility and adaptability. 

3.3 Compliance Alignment

The system supports supply-chain security objectives including SBOM transparency, secure build practices, and auditability. Logs and artifacts are retained to support compliance reviews and governance workflows. 
________________________________________

4. Methodology

4.1 Risk-Aware Classification

Traditional CI/CD pipelines rely on static thresholds (e.g., fail if critical vulnerability exists). This approach lacks contextual awareness and often blocks safe builds or allows risky ones.

The proposed system uses machine-learning classification to evaluate contextual risk based on:

•	Vulnerability severity and type
•	Dependency exposure
•	historical risk patterns
•	compliance requirements
•	developer overrides

The ML model produces a probabilistic risk score mapped to ALLOW/WARN/BLOCK categories.

4.2 Unified Security Schema

Outputs from SAST and SBOM tools are normalized into a structured schema for ML ingestion. This scheme enables:

•	consistent feature extraction
•	explainable decisions
•	cross-tool integration

4.3 Evaluation Metrics

System performance is evaluated using:

•	SBOM accuracy
•	decision latency
•	false override rate
•	decision congruence with manual review
These metrics assess both technical performance and practical usability. 
________________________________________

5. Discussion

SAST remains essential for early vulnerability detection but cannot provide complete security assurance. Detection rates remain limited, and tool inconsistency reduces reliability. 
Integrating machine learning enables contextual evaluation of vulnerabilities and supports adaptive enforcement decisions. Hybrid approaches combining deterministic scanning with AI classification address key SAST limitations, including incomplete coverage and false positives. 
The proposed pipeline demonstrates how risk-aware CI/CD systems can balance security and development velocity while supporting compliance requirements.
________________________________________

6. Conclusion

Static Application Security Testing is a foundational component of modern DevSecOps but cannot independently ensure secure deployments. Research demonstrates significant limitations in detection coverage and contextual awareness.
This paper proposes a risk-aware compliance-as-code CI/CD pipeline that integrates SAST with machine-learning-based risk classification, SBOM transparency, and automated enforcement. By combining deterministic scanning with contextual risk modeling, the system improves deployment decision accuracy while maintaining auditability and compliance alignment.
Future research should focus on improving ML explainability, integrating dynamic testing, and developing standardized evaluation benchmarks for AI-enhanced security pipelines.
________________________________________

7. Tools, SBOM Standards, and Compliance Evidence

Modern CI/CD pipelines must produce machine-readable security artifacts demonstrating secure development practices and software supply-chain transparency. U.S. Executive Order 14028 and related guidance (e.g., NIST SP 800-218 Secure Software Development Framework) require software suppliers to provide verifiable artifacts such as Software Bills of Materials (SBOMs), vulnerability-scan results, and attestations of secure development practices. 

To meet these requirements, pipelines must support:

•	Automated SBOM generation
•	Static code analysis and dependency scanning
•	Machine-readable output formats (e.g., SARIF, JSON, SPDX, CycloneDX)
•	Continuous vulnerability-database updates
•	Artifact retention for compliance and auditing

Two dominant SBOM standards are widely used in both industry and government environments:

•	SPDX (Software Package Data Exchange) – Developed by the Linux Foundation; supports JSON, tag-value, and RDF formats.

•	CycloneDX – Developed by OWASP; optimized for application security and supply-chain risk analysis.
  Both formats satisfy NTIA minimum SBOM element guidance and are commonly required in federal procurement contexts. 
________________________________________

8. Representative Tools for SAST and SBOM-Driven Security

Several widely used tools support SAST, SBOM generation, and vulnerability scanning in CI/CD pipelines:

<img width="793" height="661" alt="image" src="https://github.com/user-attachments/assets/eb1e627f-95e8-4091-90b4-124418d632f7" />

These tools collectively generate the evidence required for secure software supply-chain compliance. Each build can produce SBOM, vulnerability report, and SAST findings, which can then be evaluated by an automated risk-classification engine. 
________________________________________

9. Key Findings from Current Research

Research evaluating SAST effectiveness highlights several important observations:

•	Detection Limitations: Individual SAST tools may detect only a fraction of real-world vulnerabilities, often between roughly 11–50%. Combining tools improves coverage but does not eliminate gaps. 

•	Precision vs. Recall: Tools may demonstrate high precision in controlled benchmarks but struggle with recall in real-world codebases, leading to missed vulnerabilities or false positives. 

•	Tool Inconsistency: Results vary significantly across tools, with differing vulnerability coverage and reporting accuracy. 

•	Emerging AI Approaches: LLM-assisted static analysis shows promise for improving detection rates but may introduce higher false-positive levels without careful tuning. 

These findings suggest that SAST should not operate as a standalone security control but rather as one component of a broader, risk-aware pipeline that includes dependency scanning, dynamic testing, and risk-classification mechanisms. 
________________________________________

10. Role in an ML-Gated Risk-Aware Pipeline

Within a risk-aware CI/CD architecture, SAST outputs can serve as structured input to an automated decision engine. Instead of enforcing rigid pass/fail thresholds, the pipeline aggregates signals from:

•	Static code analysis

•	Dependency vulnerability scans

•	SBOM risk indicators

•	Build metadata

A machine-learning classifier can then evaluate overall risk and classify builds as ALLOW, WARN, or BLOCK. This approach supports both rapid development and compliance with secure software-supply-chain requirements by producing verifiable artifacts while enabling context-aware deployment decisions. 
________________________________________

11. Conclusion

SAST remains a critical component of modern secure development practices, particularly in environments requiring supply-chain transparency and regulatory compliance. While current tools face limitations in detection coverage and usability, integrating SAST with SBOM generation, vulnerability scanning, and machine-learning-based risk evaluation offers a promising path forward.
A risk-aware, compliance-aligned CI/CD pipeline that generates standardized security artifacts and leverages automated decision-making can improve both software security and regulatory readiness. Such architectures align with emerging federal requirements and represent a practical approach to balancing development velocity with security assurance. 
________________________________________

12. Selection of Tool for the Project 

Trivy was a strong choice for this project because it provides an all-in-one security scanning capability that aligns well with a risk-aware CI/CD pipeline focused on software supply-chain integrity and compliance evidence. Unlike many tools that perform only one function, Trivy can generate Software Bills of Materials (SBOMs), scan dependencies and container images for vulnerabilities, and integrate into automated pipelines with minimal configuration. This made it particularly useful for a project that required both vulnerability detection and machine-readable artifacts for compliance and risk evaluation.

Another reason Trivy was appropriate is its broad vulnerability intelligence coverage and frequent database updates. It pulls data from multiple sources including operating system advisories, language-specific vulnerability feeds, and public databases ensuring that scans reflect current threat information. Its vulnerability database is updated regularly, which supports continuous monitoring and helps maintain accurate risk assessments throughout the CI/CD process.

Trivy also supports widely accepted SBOM formats such as SPDX and CycloneDX, which are important for meeting modern software supply-chain transparency requirements and aligning with government and industry standards. The tool can both generate and scan SBOMs, allowing it to function as a central component in producing and evaluating build artifacts required for compliance frameworks like the NIST Secure Software Development Framework.

Finally, Trivy produces machine-readable outputs such as JSON and SARIF, which can be easily ingested into automated pipelines or machine-learning-based risk scoring systems. This made it especially suitable for integration into a risk-aware or ML-gated CI/CD architecture, where scan results need to be aggregated and evaluated to determine whether builds should be allowed, flagged, or blocked. Overall, Trivy’s speed, integration flexibility, standards support, and multi-function capability made it a practical and efficient choice for this project.


