# Github Actions

- [Github Actions](#github-actions)
  - [Overview](#overview)

## Overview

Based on:

- [Generation Techniques](./SBOM-Generation-Techniques.md) decision to use an **Artifact-Centric** approach
- [Output Formats](./SBOM-Output-Formats.md) decision to utilize **CycloneDX**, 
- [Tooling](./SBOM-Tooling.md) decision to use **Trivy (Aquasecurity)**

The [aquasecurity/trivy-action](https://github.com/aquasecurity/trivy-action) is selected for the pipeline.

*   **All-in-One Capability:** It utilizes **Trivy**, enabling both SBOM generation and vulnerability scanning in a single step, which simplifies pipeline configuration and maintenance.
*   **Community:** High adoption in the DevSecOps community ensures robust support and frequent updates.
