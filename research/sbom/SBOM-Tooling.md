# Evaluated Tooling

- [Evaluated Tooling](#evaluated-tooling)
  - [Syft](#syft)
    - [Deep Dive \& Unique Capabilities](#deep-dive--unique-capabilities)
    - [Why Use It](#why-use-it)
    - [Why NOT Use It](#why-not-use-it)
    - [Usage](#usage)
  - [Trivy](#trivy)
    - [Deep Dive \& Unique Capabilities](#deep-dive--unique-capabilities-1)
    - [Why Use It](#why-use-it-1)
    - [Why NOT Use It](#why-not-use-it-1)
    - [Usage](#usage-1)
  - [Decision: Trivy](#decision-trivy)
    - [Justification](#justification)

The following tools have been identified as the most effective options for a Python/Docker technology stack.

## Syft

- **Owner:** Anchore
- **GitHub Page:** [anchore/syft](https://github.com/anchore/syft)

Syft is widely regarded as the "gold standard" for generating SBOMs from container images. Unlike general-purpose scanners, Syft is purpose-built to inspect the layers of a container image (Docker/OCI) and catalog every artifact found.

### Deep Dive & Unique Capabilities

Syft excels at decomposing the Docker image filesystem. It identifies:

- **OS-level packages:** It detects the base OS (Alpine, Debian, RedHat) and lists installed system packages (APK, DPKG, RPM).
- **Application dependencies:** It scans specific directories (like `/usr/local/lib/python3.x/site-packages`) to identify Python libraries installed via Pip.

- **Orphaned binaries:** It can categorize binaries that don't belong to a package manager.

### Why Use It

Syft is designed for modern pipelines. It is a single static binary with no external dependencies. It is extremely fast and can be run immediately after the `docker build` step to generate a build artifact.

### Why NOT Use It

Syft is strictly an SBOM generator. It does **not** scan for vulnerabilities (CVEs). While this follows the Unix philosophy of "do one thing well," it requires you to manage a second tool (like **Grype**) in your pipeline to actually detect security issues. If you require a single binary to perform both generation and scanning, an all-in-one tool like **Trivy** may be operationally simpler.

### Usage
Scan a Docker image and output a CycloneDX JSON file:

Installation:
```bash
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
```

Generate SBOM for `minio/minio:RELEASE.2025-09-07T16-13-09Z-cpuv1`:

```bash
time syft docker:minio/minio:RELEASE.2025-09-07T16-13-09Z-cpuv1 -o cyclonedx-json > SBOM.json
 ✔ Loaded image                                                                                                                                                                 minio/minio:RELEASE.2025-09-07T16-13-09Z-cpuv1 
 ✔ Parsed image                                                                                                                                        sha256:9146f6ca57f0c5dc10e35711947f03aa5a7f4456a134841362f71ce80c87b1bc 
 ✔ Cataloged contents                                                                                                                                         4a2103166889bd52b3f4120247924476788271f9c911fc95857193cd2a4cbcf5 
   ├── ✔ Packages                        [365 packages]  
   ├── ✔ Executables                     [71 executables]  
   ├── ✔ File metadata                   [405 locations]  
   └── ✔ File digests                    [405 files]  
real    0m6.343s
user    0m4.285s
sys     0m1.523s
```

## Trivy

**Developer:** Aqua Security<br>
**GitHub:** [aquasecurity/trivy](https://github.com/aquasecurity/trivy)<br>

Trivy is a comprehensive, all-in-one security scanner. While widely recognized for its vulnerability scanning capabilities, it is also a powerful SBOM generator

### Deep Dive & Unique Capabilities

Trivy operates as a "Swiss Army Knife" for container security. When generating an SBOM, it performs deep inspection similar to Syft:

- **Unified Workflow:** 
  - It can generate an SBOM and immediately use that SBOM to scan for vulnerabilities without needing a second tool.
- **Broad Coverage:** 
  - Its detection mechanism covers a wide variety of ecosystems, which will enable a larger level of SBOM depth and accuracy

**Why it fits your Python/Docker stack:**

- Trivy has excellent support for Python ecosystems, identifying packages from `pip`, `pipenv`, and others. 
- It will allow us to effectively separate python dependencies from OS-level packages defined in the container image

### Why Use It

- Simplicity and consolidation are the primary drivers for Trivy. Instead of maintaining multiple tools for scanning/vulnerability detection, Trivy aims to handle the entire ecosystem. 
- Performance latency for Trivy scans appear to be significantly faster than alternatives

### Why NOT Use It

- Multi-purpose philosophy may feel bloated if the entire feature-set is not needed

### Usage

Scan a Docker image and output a CycloneDX JSON file:

Installation:
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

Generate SBOM for `minio/minio:RELEASE.2025-09-07T16-13-09Z-cpuv1`:

```bash
time trivy image --format cyclonedx --output SBOM-Trivy.json minio/minio:RELEASE.2025-09-07T16-13-09Z-cpuv1
2026-02-06T17:19:06-05:00       INFO    "--format cyclonedx" disables security scanning. Specify "--scanners vuln" explicitly if you want to include vulnerabilities in the "cyclonedx" report.
2026-02-06T17:19:06-05:00       INFO    Detected OS     family="redhat" version="8.10"
2026-02-06T17:19:06-05:00       INFO    Number of language-specific files       num=2

real    0m0.964s
user    0m0.165s
sys     0m0.130s
```

Generate SBOM for `minio/minio:RELEASE.2025-09-07T16-13-09Z-cpuv1` && scan the SBOM for any known vulnerabilities:

```bash
time trivy image --format cyclonedx --scanners vuln --output SBOM-Trivy.json minio/minio:RELEASE.2025-09-07T16-13-09Z-cpuv1
2026-02-06T17:22:05-05:00       INFO    [vulndb] Need to update DB
2026-02-06T17:22:05-05:00       INFO    [vulndb] Downloading vulnerability DB...
2026-02-06T17:22:05-05:00       INFO    [vulndb] Downloading artifact...        repo="mirror.gcr.io/aquasec/trivy-db:2"
84.02 MiB / 84.02 MiB [------------------------------------------------------------------------------------------------------------------------------------------------------------------------------] 100.00% 14.07 MiB p/s 6.2s
2026-02-06T17:22:12-05:00       INFO    [vulndb] Artifact successfully downloaded       repo="mirror.gcr.io/aquasec/trivy-db:2"
2026-02-06T17:22:12-05:00       INFO    [vuln] Vulnerability scanning is enabled
2026-02-06T17:22:13-05:00       INFO    Detected OS     family="redhat" version="8.10"
2026-02-06T17:22:13-05:00       INFO    [redhat] Detecting RHEL/CentOS vulnerabilities...       os_version="8" pkg_num=19
2026-02-06T17:22:13-05:00       INFO    Number of language-specific files       num=2
2026-02-06T17:22:13-05:00       INFO    [gobinary] Detecting vulnerabilities...
2026-02-06T17:22:13-05:00       WARN    Using severities from other vendors for some vulnerabilities. Read https://trivy.dev/docs/v0.69/guide/scanner/vulnerability#severity-selection for details.

real    0m8.047s
user    0m2.574s
sys     0m2.603s
```

## Decision: Trivy

Based on the comparison above, **Trivy** is the recommended tool for this Python/Docker stack.

### Justification

1.  **Operational Simplicity:** 
    - Trivy consolidates SBOM generation and vulnerability scanning into a single binary. 
    - This eliminates the need to manage version compatibility between two separate tools (e.g., Syft and Grype) in the CI/CD pipeline.
2.  **Performance:** 
    - In the provided benchmarks, Trivy generated the SBOM significantly faster (`0.964s`) compared to Syft (`6.343s`). - This efficiency stems from Trivy's targeted scanning approach, which focuses on package manifests and key binaries required for vulnerability detection.
3.  **Python Ecosystem Support:** 
    - Trivy meets the core requirement of distinguishing between OS-level Python packages and Pip-installed dependencies
4.  **Structured Output for Analysis:** 
    - Trivy exports to industry-standard formats (CycloneDX, SPDX) and comprehensive JSON schemas. 
    - This output is strictly structured, enabling robust downstream processing for automated auditing, policy enforcement

**Note:** Syft remains a viable alternative choice if deep-dive metadata inspection