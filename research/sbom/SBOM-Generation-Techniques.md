# Generation Techniques

- [Generation Techniques](#generation-techniques)
  - [Overview](#overview)
  - [Analysis: Source (Python) vs. Artifact (Docker)](#analysis-source-python-vs-artifact-docker)
  - [Decision](#decision)


## Overview

When generating SBOMs for containerized Python applications, a fundamental architectural decision is determining the scope of the scan.

## Analysis: Source (Python) vs. Artifact (Docker)

Approaching SBOM generation can be done at the source code level (analyzing `requirements.txt`, `poetry.lock`, or the active `venv`) or at the build artifact level (analyzing the resulting Docker image layers).

| Approach | Description | Industry Context & Citations | Pros | Cons |
| :--- | :--- | :--- | :--- | :--- |
| **Source-Centric** | Scanning the Python environment or manifest files before the build. | **Adoption:** Dominant in the "inner loop" of development and library publishing.<br>**Example:** PyPI relies on source metadata for dependency resolution.<br>**Ref:** [Python Packaging User Guide](https://packaging.python.org/) | • High fidelity for Python-specific metadata (classifiers, hashes).<br>• Easier integration into early CI stages (pre-build).<br>• Clearer distinction between direct and transitive application dependencies. | • Misses OS-level dependencies (e.g., `libssl`, `apk/apt` packages) installed in the container.<br>• Does not accurately reflect the final runtime environment. |
| **Artifact-Centric** | Scanning the final Docker image after the build. | **Adoption:** The industry standard for "outer loop" CI/CD gates and Kubernetes admission controllers.<br>**Example:** [US DoD Iron Bank](https://p1.dso.mil/) certifies images via binary scanning.<br>**Ref:** [NIST SP 800-218 (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final) emphasizes binary verification. | • Comprehensive view of the runtime environment (OS + App).<br>• Captures "phantom" dependencies introduced by base images.<br>• Industry standard for security compliance audits. | • Can be "noisy" with system packages irrelevant to the application logic.<br>• Requires the build to complete before generation. |
| **Hybrid** | Merging a source scan with a container scan. | **Adoption:** Emerging best practice for high-assurance software supply chains.<br>**Example:** [Chainguard](https://www.chainguard.dev/) and [Google's SLSA](https://slsa.dev/) framework promote build-time attestation combined with artifact analysis. | • Best of both worlds: Deep application insight + system awareness. | • Complex to implement and maintain.<br>• Potential for duplicate entries if tools do not de-duplicate effectively. |

## Decision

The **Artifact-Centric** approach is recommended for this context:

*   **Comprehensive Visibility:** Captures the full runtime environment (OS + App) by accounting for Docker image layers.
*   **Compliance Alignment:** Meets industry security standards and audit requirements.
*   **Risk Reduction:** Eliminates "blind spots" regarding OS-level dependencies inherent in source-only scans.
*   **Simplicity:** Avoids the implementation and maintenance complexity required for hybrid solutions.