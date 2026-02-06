# SBOM

This research document focuses on the generation and management of Software Bill of Materials (SBOMs), specifically tailored for Python applications and Docker container environments.

The research aims to be based standards defined within:

**RESEARCH DOC:** [NTIA Minimum Elements for an SBOM](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) (`./docs/sbom_minimum_elements_report.pdf`)
**WHAT DOES IT COVER:** Defines the baseline requirements regardless of generation technique (Executive Order 14028)

The primary goals of this investigation are to:

* **Establish Requirements for SBOM**:
  * Research the standard industry requirements for an SBOM
  * This can be found at: [SBOM-Requirements](./SBOM-Requirements.md)

*   **Explore Generation Techniques**: 
    *   Research methods for creating SBOMs that accurately reflect Python dependencies and Docker image layers. 
    *   This can be found at: [SBOM-Generation-Techniques](./SBOM-Generation-Techniques.md)
*   **Analyze Output Formats**: 
    *   Investigate standard data formats (e.g., SPDX, CycloneDX), comparing their structures and use cases to determine why one might be chosen over another. 
    *   This can be found at: [SBOM-Output-Formats](./SBOM-Output-Formats.md)
*   **Evaluate Tooling**: 
    *   Identify and benchmark the most effective tools available for this specific technology stack to streamline the SBOM generation process. 
    *   This can be found at: [SBOM-Tooling](./SBOM-Tooling.md)

*NOTE: Research will also be derived from open internet search engines including google and AI model(s). The model used for this line of research was Google Gemini 3*