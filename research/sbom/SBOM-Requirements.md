# SBOM Requirements

- [SBOM Requirements](#sbom-requirements)
  - [Research Document](#research-document)
    - [The Core Data Fields (Baseline Schema)](#the-core-data-fields-baseline-schema)
    - [Automation Support \& Formats](#automation-support--formats)
    - [Operational Practices (Pipeline Logic)](#operational-practices-pipeline-logic)
    - [Vulnerability \& VEX (False Positive Management)](#vulnerability--vex-false-positive-management)
    - [Integrity \& Provenance (Enforcement)](#integrity--provenance-enforcement)
  - [Requirement Spec](#requirement-spec)

## Research Document

**RESEARCH DOC:** [NTIA Minimum Elements for an SBOM](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) (`./docs/sbom_minimum_elements_report.pdf`)
**WHAT DOES IT COVER:** Defines the baseline requirements regardless of generation technique (Executive Order 14028)

### The Core Data Fields (Baseline Schema)

The document mandates seven specific fields to effectively track software components across the supply chain

* **Supplier Name:** Entity that creates/defines the component.
* **Component Name:** Designation assigned by the supplier.
* **Version of the Component:** Identifier specifying the specific release/change.
* **Other Unique Identifiers:** Look-up keys for databases (e.g., CPE, SWID, PURL).
* **Dependency Relationship:** The inclusion relationship (upstream X included in software Y).
* **Author of SBOM Data:** Entity creating the metadata (may differ from the supplier).
* **Timestamp:** Date and time of SBOM assembly.

**Source:** Page 9

### Automation Support & Formats

The report states that SBOMs must be machine-readable to allow for scaling and automation. It explicitly identifies three interoperable data formats:
* **SPDX** (Software Package Data eXchange)
* **CycloneDX**
* **SWID** (Software Identification) Tags

**Source:** Page 11

### Operational Practices (Pipeline Logic)

The document defines specific rules for *when* and *how* an SBOM is generated:
* **Frequency:** A new SBOM must be created with every new build or release, including updates to dependencies.
* **Depth:** Must list all primary (top-level) components and their transitive dependencies.
* **Known Unknowns:** If the full graph is not known, the author must explicitly distinguish between "no dependencies" and "unknown dependencies."

**Source:** Page 12

### Vulnerability & VEX (False Positive Management)

The report distinguishes between "Vulnerability" (static defect) and "Exploitability" (risk context). It introduces the concept of **VEX (Vulnerability Exploitability eXchange)** to communicate whether a component is actually "affected" by a vulnerability in the context of the deployed software.

**Source:** Page 17

### Integrity & Provenance (Enforcement)

While not in the absolute minimums, the "Recommended Data Fields" section emphasizes:
* **Cryptographic Hashes:** Generating hashes for components to verify exact bits used.
* **Digital Signatures:** Signing the SBOM to ensure authenticity and prevent tampering.

**Source:** Page 14, 16

## Requirement Spec

| REQ-ID | Requirement Name | Description |
| :--- | :--- | :--- |
| **REQ-01** | Supplier Name | The SBOM must identify the entity that creates, defines, and identifies the component. |
| **REQ-02** | Component Name | The SBOM must include the designation assigned to a unit of software defined by the original supplier. |
| **REQ-03** | Component Version | The SBOM must include an identifier used by the supplier to specify a change in software from a previously identified version. |
| **REQ-04** | Unique Identifiers | The SBOM must include other identifiers (e..g., CPE, PURL, SWID) that are used to look up data in other databases. |
| **REQ-05** | Dependency Relationship | The SBOM must represent the relationship characterizing upstream components included in the software. |
| **REQ-06** | Author | The SBOM must identify the entity that created the SBOM data. |
| **REQ-07** | Timestamp | The SBOM must record the date and time of the SBOM data assembly. |
| **REQ-08** | Automation | The SBOM must be generated in a machine-readable format (SPDX, CycloneDX, or SWID). |
| **REQ-09** | Frequency | A new SBOM must be created with every new build or release, including updates to dependencies. |
| **REQ-10** | Depth | The SBOM must list all primary (top-level) components and their transitive dependencies. |
| **REQ-11** | Known Unknowns | The SBOM author must explicitly distinguish between "no dependencies" and "unknown dependencies" when the dependency graph is incomplete. |
| **REQ-12** | VEX | The solution must support VEX (Vulnerability Exploitability eXchange) to communicate whether a component is affected by a vulnerability. |
| **REQ-13** | Integrity | Components should have cryptographic hashes to verify the exact bits used. |
| **REQ-14** | Provenance | The SBOM should be digitally signed to ensure authenticity and prevent tampering. |