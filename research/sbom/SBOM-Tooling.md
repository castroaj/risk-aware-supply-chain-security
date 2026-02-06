# Evaluated Tooling

- [Evaluated Tooling](#evaluated-tooling)
  - [Syft](#syft)
  - [CycloneDX-Python](#cyclonedx-python)
  - [Trivy](#trivy)

The following tools have been identified as the most effective options for a Python/Docker technology stack.

## Syft
Developed by Anchore, Syft is a CLI tool and Go library for generating SBOMs from container images and filesystems. It is widely considered the "gold standard" for image-based generation.
*   **GitHub:** [anchore/syft](https://github.com/anchore/syft)
*   **Key Features:** Excellent Docker support, supports both SPDX and CycloneDX output, can scan a running container, and separates OS packages from Python packages clearly.

## CycloneDX-Python
The official reference implementation for generating SBOMs specifically for Python environments.
*   **GitHub:** [CycloneDX/cyclonedx-python](https://github.com/CycloneDX/cyclonedx-python)
*   **Key Features:** Native understanding of Python virtual environments, Poetry, and Pipenv. It generates highly accurate Python metadata that generic image scanners might miss.

## Trivy
While primarily known as a vulnerability scanner, Trivy (by Aqua Security) possesses robust SBOM generation capabilities.
*   **GitHub:** [aquasecurity/trivy](https://github.com/aquasecurity/trivy)
*   **Key Features:** All-in-one tool (can generate the SBOM and immediately scan it for CVEs), extremely fast, and offers easy CI/CD integration.