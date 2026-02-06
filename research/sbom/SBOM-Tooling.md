# Evaluated Tooling

- [Evaluated Tooling](#evaluated-tooling)
  - [Syft](#syft)
    - [Deep Dive \& Unique Capabilities](#deep-dive--unique-capabilities)
    - [Why Use It](#why-use-it)
    - [Why NOT Use It](#why-not-use-it)
    - [Usage](#usage)

The following tools have been identified as the most effective options for a Python/Docker technology stack.

## Syft

**Developer:** Anchore<br>
**GitHub:** [anchore/syft](https://github.com/anchore/syft)<br>

Syft is widely regarded as the "gold standard" for generating SBOMs from container images. Unlike general-purpose scanners, Syft is purpose-built to inspect the layers of a container image (Docker/OCI) and catalog every artifact found.

### Deep Dive & Unique Capabilities
Syft excels at decomposing the Docker image filesystem. It identifies:

- **OS-level packages:** It detects the base OS (Alpine, Debian, RedHat) and lists installed system packages (APK, DPKG, RPM).
- **Application dependencies:** It scans specific directories (like `/usr/local/lib/python3.x/site-packages`) to identify Python libraries installed via Pip.

- **Orphaned binaries:** It can categorize binaries that don't belong to a package manager.

**Why it fits your Python/Docker stack:**
- Syft is capable of distinguishing between Python packages installed via the OS package manager (e.g., `apt-get install python3-requests`) and those installed via Pip. This distinction is crucial for vulnerability management, as the remediation steps differ.

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

Scan Image: (fetched from default mirror)

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

