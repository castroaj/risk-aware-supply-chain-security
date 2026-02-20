
# Output Formats

- [Output Formats](#output-formats)
  - [SPDX (Software Package Data Exchange)](#spdx-software-package-data-exchange)
    - [Primary Use Cases](#primary-use-cases)
    - [Spec Sample](#spec-sample)
  - [CycloneDX](#cyclonedx)
    - [Primary Use Cases](#primary-use-cases-1)
- [Decision](#decision)

While various formats exist, the industry has consolidated around two primary standards.

## SPDX (Software Package Data Exchange)

Maintained by the Linux Foundation, SPDX is an ISO standard (ISO/IEC 5962:2021). It was originally designed to facilitate license compliance and intellectual property verification across organizations.

### Primary Use Cases 

*   **License Compliance:** 
    *   Analyzing and adhering to open source licenses (GPL, Apache, MIT).
*   **Intellectual Property:** 
    *   Tracking copyright and ownership across organizational boundaries.
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

# Decision

After evaluating the standards, **CycloneDX** has been selected as the primary format for our software bill of materials.

*   **Security Focus:** 
    *   Built specifically for application security, it aligns perfectly with our requirements for robust vulnerability management and risk analysis.
*   **VEX Capabilities:** 
    *   Native support for VEX (Vulnerability Exploitability Exchange) allows us to efficiently handle false positives and communicate exploitability status.
*   **Automation Friendly:** 
    *   The lightweight JSON format and utilization of Package URLs (PURL) are optimized for integration into high-velocity CI/CD pipelines.
*   **Tooling Integration:** 
    *   It serves as the native format for OWASP Dependency-Track, enabling continuous component analysis out of the box.
*   **Compliance:** 
    *   It satisfies NTIA minimum elements for federal requirements while offering superior operational utility for engineering teams.
