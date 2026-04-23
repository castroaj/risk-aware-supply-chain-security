# ML Feature Extraction: Risk-Based Classification Model

- [ML Feature Extraction: Risk-Based Classification Model](#ml-feature-extraction-risk-based-classification-model)
- [I. Feature Definition](#i-feature-definition)
- [II. Feature Extraction](#ii-feature-extraction)
  - [SBOM Features](#sbom-features)
    - [Total Dependency Count](#total-dependency-count)
  - [Vulnerability Scan](#vulnerability-scan)
    - [Vulnerability Total](#vulnerability-total)
    - [Critical CVE Count](#critical-cve-count)
    - [High CVE Count](#high-cve-count)
    - [CVSS GE 7 Count](#cvss-ge-7-count)
    - [Max CVSS](#max-cvss)
    - [Unique CWE Count](#unique-cwe-count)
    - [Top25 CWE Count](#top25-cwe-count)
  - [SAST Scan Features](#sast-scan-features)
    - [SemGrep Total](#semgrep-total)
    - [SemGrep High Count](#semgrep-high-count)


# I. Feature Definition

The following are the features relevant for the classification model

- SBOM (Trivy)
  - `total_dependency_count`
- Vulnerability Scan (Trivy)
  - `vuln_total`
  - `critical_cve_count`
  - `high_cve_count`
  - `cvss_ge_7_count`
  - `max_cvss`
  - `unique_cwe_count`
  - `top25_cwe_count`
- SAST Scan (Semgrep)
  - `semgrep_total`
  - `semgrep_high_count`

# II. Feature Extraction

## SBOM Features

The following features are derived from the `components` section of the SBOM file produced by the [`aquasecurity/trivy`](https://github.com/aquasecurity/trivy) tool

### Total Dependency Count

**WHAT:**
- The `total_dependency_count` is the number of software components within the software stack. 
- It is comprised of individual components each corresponding to an individual building block of the stack. 
- This includes applications, frameworks, libraries, and containers.

**WHY:**
- An increase in the number of dependencies will increase the attack surface of the application.
- An increase in the number of dependencies increases the difficultly of maintaining software, which likely leads to more developer mistakes

**WHERE:**
- The `total_dependency_count` is derived from the length of the `.components` JSON array contained within the SBOM file. 

## Vulnerability Scan

The following features are derived from the `vulnerabilities` section of the SBOM file produced by the [`aquasecurity/trivy`](https://github.com/aquasecurity/trivy) tool. Some of the features reference additional information mentioned below.

### Vulnerability Total

**WHAT:**
- The `vuln_total` represents the total number of individual CVEs found within the software stack.

**WHY:**
- The total number of vulnerabilities is a strong indicator that a software project is poorly maintained
- It could mean that it has not been updated recently
- It could mean that the developer relies on a software stack that is no longer maintained
- It could mean that the developer choose the wrong software stack

**WHERE:**
- The `vuln_total` is derived from the length of the `.vulnerabilities` section of JSON array contained within the SBOM file.

### Critical CVE Count

**WHAT:**
- Each vulnerability contains a series of ratings from a variety of sources, each of which should provide a severity level in that authority's opinion
- The severity level is measured with a categorical word, including `critical` which is relevant for this feature

**WHY:**
- Severity level is the core indicator that a CVE poses a high level of risk to a system
- CVEs marked as `critical` should not reach a production build, unless overwhelming contrary evidence is provided

**WHERE:**
- The `critical_cve_count` is derived by taking the highest `severity` score from the `.vulnerabilities.{VULN}.ratings.{SOURCE}.severity`. 
- If that severity is `critical`, than this count is incremented

### High CVE Count

**WHAT:**
- Each vulnerability contains a series of ratings from a variety of sources, each of which should provide a severity level in that authority's opinion
- The severity level is measured with a categorical word, including `high` which is relevant for this feature

**WHY:**
- Severity level is the core indicator that a CVE poses a high level of risk to a system
- CVEs marked as `high` should be inspected and heavily scrutinized by the development team
- An accumulation of many `high` severity CVEs may be put your system at more risk than if a single `critical` CVE was present

**WHERE:**
- The `critical_cve_count` is derived by taking the highest `severity` score from the `.vulnerabilities.{VULN}.ratings.{SOURCE}.severity`. 
- If that severity is `high`, than this count is incremented

### CVSS GE 7 Count

**WHAT:**
- Each vulnerability contains a series of ratings from a variety of sources, each of which should provide a CVSS score representing authority's opinion in numeric form
**WHY:**
- A CVSS score of 7.0 or higher corresponds to High and Critical severity vulnerabilities.
- This metric provides a count of serious vulnerabilities based on the numeric score, removing ambiguity from categorical labels.

**WHERE:**
- The `cvss_ge_7_count` is derived by taking the highest `score` from the `.vulnerabilities.{VULN}.ratings.{SOURCE}.score`.
- If that score is greater than or equal to `7.0`, than this count is incremented.

### Max CVSS

**WHAT:**
- The `max_cvss` represents the highest Common Vulnerability Scoring System (CVSS) score found amongst all vulnerabilities in the software stack.
- It pinpoints the single most severe flaw present in the system, rated on a scale of `0.0` to `10.0`.

**WHY:**
- This metric defines the ceiling of risk for the application as a system is often considered only as secure as its weakest link.
- A high maximum score signals immediate urgency, whereas a lower maximum indicates that no individual flaw is catastrophic.

**WHERE:**
- The `max_cvss` is derived by iterating through all `.vulnerabilities`, extracting the highest value from `.vulnerabilities.{VULN}.ratings.{SOURCE}.score`, and determining the maximum.

### Unique CWE Count

**WHAT:**
- The `unique_cwe_count` identifies the number of distinct Common Weakness Enumeration (CWE) categories present within the identified vulnerabilities.
- This metric focuses on the variety of weakness types rather than the raw count of specific CVEs.

**WHY:**
- Diverse weakness types suggest a broader attack surface
- It can indicate systemic issues where multiple different coding or design patterns are failing security best practices.

**WHERE:**
- The `unique_cwe_count` is derived by extracting the `cwes` list from each item in the `.vulnerabilities` array, creating a set of unique values, and counting them.

### Top25 CWE Count

**WHAT:**
- The `top25_cwe_count` is the total number of vulnerabilities that are categorized under the MITRE "Top 25 Most Dangerous Software Weaknesses."
- These weaknesses are demonstrably the most dangerous, frequent, and impactful issues currently facing the software industry.

**WHY:**
- Weaknesses on the Top 25 list are often the first targets for attackers because they are well-documented and effective.
- A high count indicates that the software stack contains "low-hanging fruit" for potential exploits.

**WHERE:**
- The `top25_cwe_count` is derived by cross-referencing extracted `cwes` from the `.vulnerabilities` section against the standard list of Top 25 CWEs.

## SAST Scan Features

> **Deferred — out of scope for current implementation.** `semgrep_total` and
> `semgrep_high_count` have been removed from the active feature vector in
> `sbom_extractor.py`. SAST requires source code, which is unavailable for the
> pre-built public Docker images used in the current training pipeline (Use Case A).
> These features are retained here as the design specification for a future
> first-party build pipeline (Use Case B). See
> `research/ML_model/semgrep-feature-analysis.md` for full rationale.

The following features are derived from the `results` section of the SemGrep output JSON file produced by the [`semgrep/semgrep`](https://github.com/semgrep/semgrep) tool

### SemGrep Total

**WHAT:**
- The `semgrep_total` is the total count of issues and patterns matched by the Semgrep engine against the source code.
- It aggregates all static analysis findings, including security hotspots, correctness issues, and performance anti-patterns.

**WHY:**
- A high total count indicates that the codebase may suffer from poor code quality or a lack of standardized development practices.
- It serves as a proxy for technical debt

**WHERE:**
- The `semgrep_total` is derived from the length of the `.results` JSON array found in the Semgrep output file.

### SemGrep High Count

**WHAT:**
- The `semgrep_high_count` represents the number of Semgrep findings that are assigned the highest severity level.
- This metric filters the noise of general code quality issues to focus specifically on critical security flaws and errors.

**WHY:**
- These findings usually correspond to known bad patterns that lead to vulnerabilities such as SQL injection, XSS, or hardcoded credentials.
- A non-zero count here suggests the application has explicit security defects that need remediation before deployment.

**WHERE:**
- The `semgrep_high_count` is derived by examining the `severity` field (typically `.extra.severity`) of each entry in the `.results` array.
- If the value matches `ERROR` (Semgrep's high severity label), this count is incremented.

