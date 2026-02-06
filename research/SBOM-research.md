# SBOM
- [SBOM](#sbom)
- [Overview](#overview)
- [SBOM Requirements](#sbom-requirements)
  - [The Core Data Fields (Baseline Schema)](#the-core-data-fields-baseline-schema)
  - [Automation Support \& Formats](#automation-support--formats)
  - [Operational Practices (Pipeline Logic)](#operational-practices-pipeline-logic)
  - [Vulnerability \& VEX (False Positive Management)](#vulnerability--vex-false-positive-management)
  - [Integrity \& Provenance (Enforcement)](#integrity--provenance-enforcement)
- [Generation Techniques](#generation-techniques)
  - [Analysis: Source (Python) vs. Artifact (Docker)](#analysis-source-python-vs-artifact-docker)
    - [Decision](#decision)
- [Output Formats](#output-formats)
  - [SPDX (Software Package Data Exchange)](#spdx-software-package-data-exchange)
    - [Primary Use Cases](#primary-use-cases)
    - [Spec Sample](#spec-sample)
  - [CycloneDX](#cyclonedx)
    - [Primary Use Cases](#primary-use-cases-1)
- [Evaluated Tooling (TODO - Unfinished)](#evaluated-tooling-todo---unfinished)
  - [1. Syft](#1-syft)
  - [2. CycloneDX-Python](#2-cyclonedx-python)
  - [3. Trivy](#3-trivy)


# Overview

This research document focuses on the generation and management of Software Bill of Materials (SBOMs), specifically tailored for Python applications and Docker container environments.

The primary goals of this investigation are to:

*   **Explore Generation Techniques**: Research methods for creating SBOMs that accurately reflect Python dependencies and Docker image layers.
*   **Analyze Output Formats**: Investigate standard data formats (e.g., SPDX, CycloneDX), comparing their structures and use cases to determine why one might be chosen over another.
*   **Evaluate Tooling**: Identify and benchmark the most effective tools available for this specific technology stack to streamline the SBOM generation process.

# SBOM Requirements

**RESEARCH DOC:** [NTIA Minimum Elements for an SBOM](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) (`/docs/sbom_minimum_elements_report.pdf`)
**WHAT DOES IT COVER:** Defines the baseline requirements regardless of generation technique (Executive Order 14028)

## The Core Data Fields (Baseline Schema)

The document mandates seven specific fields to effectively track software components across the supply chain

* **Supplier Name:** Entity that creates/defines the component.
* **Component Name:** Designation assigned by the supplier.
* **Version of the Component:** Identifier specifying the specific release/change.
* **Other Unique Identifiers:** Look-up keys for databases (e.g., CPE, SWID, PURL).
* **Dependency Relationship:** The inclusion relationship (upstream X included in software Y).
* **Author of SBOM Data:** Entity creating the metadata (may differ from the supplier).
* **Timestamp:** Date and time of SBOM assembly.

**Source:** Page 9

## Automation Support & Formats

The report states that SBOMs must be machine-readable to allow for scaling and automation. It explicitly identifies three interoperable data formats:
* **SPDX** (Software Package Data eXchange)
* **CycloneDX**
* **SWID** (Software Identification) Tags

**Source:** Page 11

## Operational Practices (Pipeline Logic)

The document defines specific rules for *when* and *how* an SBOM is generated:
* **Frequency:** A new SBOM must be created with every new build or release, including updates to dependencies.
* **Depth:** Must list all primary (top-level) components and their transitive dependencies.
* **Known Unknowns:** If the full graph is not known, the author must explicitly distinguish between "no dependencies" and "unknown dependencies."

**Source:** Page 12

## Vulnerability & VEX (False Positive Management)

The report distinguishes between "Vulnerability" (static defect) and "Exploitability" (risk context). It introduces the concept of **VEX (Vulnerability Exploitability eXchange)** to communicate whether a component is actually "affected" by a vulnerability in the context of the deployed software.

**Source:** Page 17

## Integrity & Provenance (Enforcement)
While not in the absolute minimums, the "Recommended Data Fields" section emphasizes:
* **Cryptographic Hashes:** Generating hashes for components to verify exact bits used.
* **Digital Signatures:** Signing the SBOM to ensure authenticity and prevent tampering.

**Source:** Page 14, 16

# Generation Techniques

When generating SBOMs for containerized Python applications, a fundamental architectural decision is determining the scope of the scan.

## Analysis: Source (Python) vs. Artifact (Docker)

Approaching SBOM generation can be done at the source code level (analyzing `requirements.txt`, `poetry.lock`, or the active `venv`) or at the build artifact level (analyzing the resulting Docker image layers).

| Approach | Description | Industry Context & Citations | Pros | Cons |
| :--- | :--- | :--- | :--- | :--- |
| **Source-Centric** | Scanning the Python environment or manifest files before the build. | **Adoption:** Dominant in the "inner loop" of development and library publishing.<br>**Example:** PyPI relies on source metadata for dependency resolution.<br>**Ref:** [Python Packaging User Guide](https://packaging.python.org/) | • High fidelity for Python-specific metadata (classifiers, hashes).<br>• Easier integration into early CI stages (pre-build).<br>• Clearer distinction between direct and transitive application dependencies. | • Misses OS-level dependencies (e.g., `libssl`, `apk/apt` packages) installed in the container.<br>• Does not accurately reflect the final runtime environment. |
| **Artifact-Centric** | Scanning the final Docker image after the build. | **Adoption:** The industry standard for "outer loop" CI/CD gates and Kubernetes admission controllers.<br>**Example:** [US DoD Iron Bank](https://p1.dso.mil/) certifies images via binary scanning.<br>**Ref:** [NIST SP 800-218 (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final) emphasizes binary verification. | • Comprehensive view of the runtime environment (OS + App).<br>• Captures "phantom" dependencies introduced by base images.<br>• Industry standard for security compliance audits. | • Can be "noisy" with system packages irrelevant to the application logic.<br>• Requires the build to complete before generation. |
| **Hybrid** | Merging a source scan with a container scan. | **Adoption:** Emerging best practice for high-assurance software supply chains.<br>**Example:** [Chainguard](https://www.chainguard.dev/) and [Google's SLSA](https://slsa.dev/) framework promote build-time attestation combined with artifact analysis. | • Best of both worlds: Deep application insight + system awareness. | • Complex to implement and maintain.<br>• Potential for duplicate entries if tools do not de-duplicate effectively. |

### Decision

The **Artifact-Centric** approach is recommended for this context:

*   **Comprehensive Visibility:** Captures the full runtime environment (OS + App) by accounting for Docker image layers.
*   **Compliance Alignment:** Meets industry security standards and audit requirements.
*   **Risk Reduction:** Eliminates "blind spots" regarding OS-level dependencies inherent in source-only scans.
*   **Simplicity:** Avoids the implementation and maintenance complexity required for hybrid solutions.

# Output Formats

While various formats exist, the industry has consolidated around two primary standards.

## SPDX (Software Package Data Exchange)
Maintained by the Linux Foundation, SPDX is an ISO standard (ISO/IEC 5962:2021). It was originally designed to facilitate license compliance and intellectual property verification across organizations.

### Primary Use Cases 

*   **License Compliance:** Analyzing and adhering to open source licenses (GPL, Apache, MIT).
*   **Intellectual Property:** Tracking copyright and ownership across organizational boundaries.
*   **Regulatory Adherence:** 
    *   Critical for meeting government mandates, specifically [Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)
    *   As an ISO standard, SPDX is a trusted format for delivering the [NTIA Minimum Elements](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) required to secure the federal software supply chain.
*   **Archival:** Long-term storage of software bill of materials data in a standardized way.

### Spec Sample

```spdx
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: Sample Project Spec v1.0
DocumentNamespace: http://spdx.org/spdxdocs/sample-project-1.0-4f8e9a
Creator: Person: Jane Doe (jane@example.com)
Created: 2023-10-27T12:00:00Z

##### Main Package Information
PackageName: AwesomeApp
SPDXID: SPDXRef-Package-Main
PackageVersion: 1.0.0
PackageDownloadLocation: git+https://github.com/example/awesomeapp.git
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT
PackageCopyrightText: Copyright 2023 Example Corp.

##### File Information
FileName: ./src/main.py
SPDXID: SPDXRef-File-MainPy
FileChecksum: SHA1: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
LicenseConcluded: MIT
FileCopyrightText: Copyright 2023 Example Corp.

##### External Dependency
PackageName: requests
SPDXID: SPDXRef-Package-Requests
PackageVersion: 2.31.0
PackageDownloadLocation: https://pypi.org/project/requests/
PackageLicenseConcluded: Apache-2.0
PackageCopyrightText: Copyright 2023 Kenneth Reitz

##### Relationships
Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-Main
Relationship: SPDXRef-Package-Main CONTAINS SPDXRef-File-MainPy
Relationship: SPDXRef-Package-Main DEPENDS_ON SPDXRef-Package-Requests
```

## CycloneDX

Maintained by the **OWASP Foundation**, CycloneDX is a lightweight standard designed specifically for application security contexts and supply chain component analysis. Unlike SPDX's historical focus on legal compliance, CycloneDX was built from the ground up to support vulnerability management.

### Primary Use Cases 

*   **Vulnerability Analysis:** The format is optimized for high-volume automated processing to identify security risks (CVEs) in modern DevOps pipelines.
*   **Advanced Security Workflows:**
    *   Native support for **[VEX (Vulnerability Exploitability Exchange)](https://cyclonedx.org/capabilities/vex/)**, allowing vendors to signal that a specific vulnerability is "not affected" in their product.
    *   Extends beyond code to support **[SaaSBOM](https://cyclonedx.org/capabilities/saasbom/)** (Services), **HBOM** (Hardware), and **OBOM** (Operations).
*   **Ecosystem Integration:**
    *   The native format for [OWASP Dependency-Track](https://dependencytrack.org/), the industry-standard continuous component analysis platform.
    *   Heavily relies on **[Package URLs (PURL)](https://github.com/package-url/purl-spec)** to facilitate accurate component lookup across different repositories.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2023-10-27T12:00:00Z",
    "component": {
      "name": "AwesomeApp",
      "version": "1.0.0",
      "type": "application",
      "purl": "pkg:pypi/awesomeapp@1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "purl": "pkg:pypi/requests@2.31.0",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0"
          }
        }
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:pypi/awesomeapp@1.0.0",
      "dependsOn": [
        "pkg:pypi/requests@2.31.0"
      ]
    }
}
```

# Evaluated Tooling (TODO - Unfinished)

The following tools have been identified as the most effective options for a Python/Docker technology stack.

## 1. Syft
Developed by Anchore, Syft is a CLI tool and Go library for generating SBOMs from container images and filesystems. It is widely considered the "gold standard" for image-based generation.
*   **GitHub:** [anchore/syft](https://github.com/anchore/syft)
*   **Key Features:** Excellent Docker support, supports both SPDX and CycloneDX output, can scan a running container, and separates OS packages from Python packages clearly.

## 2. CycloneDX-Python
The official reference implementation for generating SBOMs specifically for Python environments.
*   **GitHub:** [CycloneDX/cyclonedx-python](https://github.com/CycloneDX/cyclonedx-python)
*   **Key Features:** Native understanding of Python virtual environments, Poetry, and Pipenv. It generates highly accurate Python metadata that generic image scanners might miss.

## 3. Trivy
While primarily known as a vulnerability scanner, Trivy (by Aqua Security) possesses robust SBOM generation capabilities.
*   **GitHub:** [aquasecurity/trivy](https://github.com/aquasecurity/trivy)
*   **Key Features:** All-in-one tool (can generate the SBOM and immediately scan it for CVEs), extremely fast, and offers easy CI/CD integration.