# Github Actions

- [Github Actions](#github-actions)
  - [Overview](#overview)
  - [Candidate Evaluation](#candidate-evaluation)
  - [Decision](#decision)

## Overview

Based on the [Generation Techniques](./SBOM-Generation-Techniques.md) decision to use an **Artifact-Centric** approach and the [Output Formats](./SBOM-Output-Formats.md) decision to utilize **CycloneDX**, we require a GitHub Action capable of inspecting built container images (Docker) and producing compliant JSON output.

## Candidate Evaluation

| Action | Underlying Tool | Alignment | Pros | Cons |
| :--- | :--- | :--- | :--- | :--- |
| **anchore/sbom-action** | **Syft** | **High** | • **Native CycloneDX:** Default output format aligns with our decision.<br>• **Artifact-Centric:** Designed specifically to scan container images and filesystems.<br>• **Compliance:** Excellent coverage of the NTIA Minimum Elements (REQ-01 to REQ-07).<br>• **Provenance:** Easy integration with `sigstore/cosign` for signing. | • Focuses solely on generation; vulnerability scanning requires a separate step/action (Grype). |
| **aquasecurity/trivy-action** | **Trivy** | **Medium** | • **All-in-One:** Performs both SBOM generation and Vulnerability scanning.<br>• **Popularity:** Widely adopted in the DevSecOps community. | • **Optimization:** Primarily optimized for finding vulnerabilities, not generating strict compliance documents.<br>• **Overhead:** May be overkill if only the SBOM artifact is required for this stage. |
| **docker/sbom-cli-plugin** | **BuildKit** | **Low** | • **Integrated:** Can generate SBOMs directly during `docker build`. | • **Opacity:** Harder to extract and manipulate the SBOM as a distinct artifact in the CI pipeline for signing/attestation workflows. |

## Decision

The **aquasecurity/trivy-action** is selected for the pipeline.

*   **All-in-One Capability:** It utilizes **Trivy**, enabling both SBOM generation and vulnerability scanning in a single step, which simplifies pipeline configuration and maintenance.
*   **Requirement Satisfaction:**
    *   **REQ-08 (Automation):** Supports producing machine-readable CycloneDX JSON output.
    *   **REQ-09 (Frequency):** Can be triggered on every workflow run.
    *   **REQ-13 (Integrity):** Generates artifacts suitable for hashing and signing.
*   **Community:** High adoption in the DevSecOps community ensures robust support and frequent updates.

