# SBOM
- [SBOM](#sbom)
- [Overview](#overview)
  - [Generation Techniques](#generation-techniques)
    - [Analysis: Source (Python) vs. Artifact (Docker)](#analysis-source-python-vs-artifact-docker)
      - [Decision](#decision)
      - [Relevant Research](#relevant-research)
  - [Output Formats](#output-formats)
    - [SPDX (Software Package Data Exchange)](#spdx-software-package-data-exchange)
    - [CycloneDX](#cyclonedx)
  - [Evaluated Tooling](#evaluated-tooling)
    - [1. Syft](#1-syft)
    - [2. CycloneDX-Python](#2-cyclonedx-python)
    - [3. Trivy](#3-trivy)


# Overview

This research document focuses on the generation and management of Software Bill of Materials (SBOMs), specifically tailored for Python applications and Docker container environments.

The primary goals of this investigation are to:

*   **Explore Generation Techniques**: Research methods for creating SBOMs that accurately reflect Python dependencies and Docker image layers.
*   **Analyze Output Formats**: Investigate standard data formats (e.g., SPDX, CycloneDX), comparing their structures and use cases to determine why one might be chosen over another.
*   **Evaluate Tooling**: Identify and benchmark the most effective tools available for this specific technology stack to streamline the SBOM generation process.

## Generation Techniques

When generating SBOMs for containerized Python applications, a fundamental architectural decision is determining the scope of the scan.

### Analysis: Source (Python) vs. Artifact (Docker)

Approaching SBOM generation can be done at the source code level (analyzing `requirements.txt`, `poetry.lock`, or the active `venv`) or at the build artifact level (analyzing the resulting Docker image layers).

| Approach | Description | Industry Context & Citations | Pros | Cons |
| :--- | :--- | :--- | :--- | :--- |
| **Source-Centric** | Scanning the Python environment or manifest files before the build. | **Adoption:** Dominant in the "inner loop" of development and library publishing.<br>**Example:** [PyPI](https://pypi.org/) relies on source metadata for dependency resolution.<br>**Ref:** [Python Packaging User Guide](https://packaging.python.org/). | • High fidelity for Python-specific metadata (classifiers, hashes).<br>• Easier integration into early CI stages (pre-build).<br>• Clearer distinction between direct and transitive application dependencies. | • Misses OS-level dependencies (e.g., `libssl`, `apk/apt` packages) installed in the container.<br>• Does not accurately reflect the final runtime environment. |
| **Artifact-Centric** | Scanning the final Docker image after the build. | **Adoption:** The industry standard for "outer loop" CI/CD gates and Kubernetes admission controllers.<br>**Example:** [US DoD Iron Bank](https://p1.dso.mil/) certifies images via binary scanning.<br>**Ref:** [NIST SP 800-218 (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final) emphasizes binary verification. | • Comprehensive view of the runtime environment (OS + App).<br>• Captures "phantom" dependencies introduced by base images.<br>• Industry standard for security compliance audits. | • Can be "noisy" with system packages irrelevant to the application logic.<br>• Requires the build to complete before generation. |
| **Hybrid** | Merging a source scan with a container scan. | **Adoption:** Emerging best practice for high-assurance software supply chains.<br>**Example:** [Chainguard](https://www.chainguard.dev/) and [Google's SLSA](https://slsa.dev/) framework promote build-time attestation combined with artifact analysis. | • Best of both worlds: Deep application insight + system awareness. | • Complex to implement and maintain.<br>• Potential for duplicate entries if tools do not de-duplicate effectively. |

#### Decision

The **Artifact-Centric** approach is recommended for this context:

*   **Comprehensive Visibility:** Captures the full runtime environment (OS + App) by accounting for Docker image layers.
*   **Compliance Alignment:** Meets industry security standards and audit requirements.
*   **Risk Reduction:** Eliminates "blind spots" regarding OS-level dependencies inherent in source-only scans.
*   **Simplicity:** Avoids the implementation and maintenance complexity required for hybrid solutions.

#### Relevant Research

*   [NTIA Minimum Elements for an SBOM](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) - Defines the baseline requirements regardless of generation technique (Executive Order 14028).

## Output Formats

While various formats exist, the industry has consolidated around two primary standards.

### SPDX (Software Package Data Exchange)
Maintained by the Linux Foundation, SPDX is an ISO standard (ISO/IEC 5962:2021). It was originally designed to facilitate license compliance and intellectual property verification across organizations.
*   **Primary Use Case:** Legal compliance, license tracking, and heavy regulatory environments.
*   **Resource:** [SPDX Specification & Research](https://spdx.dev/specifications/)

### CycloneDX
A flagship OWASP project, CycloneDX is a "security-first" standard designed specifically for application security contexts and supply chain component analysis.
*   **Primary Use Case:** Vulnerability management, automated security scanning, and VEX (Vulnerability Exploitability Exchange) implementation.
*   **Resource:** [OWASP CycloneDX Specification](https://cyclonedx.org/)

**Comparison:** Choose **SPDX** if the primary driver is Open Source license compliance. Choose **CycloneDX** if the primary driver is DevSecOps automation and vulnerability tracking.

## Evaluated Tooling

The following tools have been identified as the most effective options for a Python/Docker technology stack.

### 1. Syft
Developed by Anchore, Syft is a CLI tool and Go library for generating SBOMs from container images and filesystems. It is widely considered the "gold standard" for image-based generation.
*   **GitHub:** [anchore/syft](https://github.com/anchore/syft)
*   **Key Features:** Excellent Docker support, supports both SPDX and CycloneDX output, can scan a running container, and separates OS packages from Python packages clearly.

### 2. CycloneDX-Python
The official reference implementation for generating SBOMs specifically for Python environments.
*   **GitHub:** [CycloneDX/cyclonedx-python](https://github.com/CycloneDX/cyclonedx-python)
*   **Key Features:** Native understanding of Python virtual environments, Poetry, and Pipenv. It generates highly accurate Python metadata that generic image scanners might miss.

### 3. Trivy
While primarily known as a vulnerability scanner, Trivy (by Aqua Security) possesses robust SBOM generation capabilities.
*   **GitHub:** [aquasecurity/trivy](https://github.com/aquasecurity/trivy)
*   **Key Features:** All-in-one tool (can generate the SBOM and immediately scan it for CVEs), extremely fast, and offers easy CI/CD integration.