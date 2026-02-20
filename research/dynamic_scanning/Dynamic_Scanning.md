# Dynamic Scanning Research
## Risk-Aware Compliance-as-Code CI/CD Pipeline

**Status:** Draft Research Summary  
**Last Updated:** Feb 2026

---

## 1. Purpose

This document summarizes research into **dynamic scanning approaches** suitable
for integration into the project’s secure CI/CD pipeline.

Dynamic scanning complements static analysis (Bandit) by identifying risks in:

- runtime artifacts
- container images
- deployed application environments

The goal is to recommend a scanning strategy that supports:

- Software supply chain integrity
- EO 14028 compliance expectations
- ML-based risk gating (ALLOW/WARN/BLOCK)

---

## 2. Dynamic Scanning Definition (Project Context)

In this project, *dynamic scanning* refers to security evaluation performed on
built artifacts rather than only source code.

This includes:

- Container vulnerability scanning
- Dependency CVE detection
- Optional runtime DAST against a running service

Dynamic scanning provides risk signals that improve deployment decisions.

---


## 3. Candidate Tool Options

### Option A: Trivy Image & Vulnerability Scanning (Recommended)

**What it does:**

- Scans container images for known CVEs
- Generates SBOMs
- Produces structured JSON outputs

**Strengths:**

- Easy GitHub Actions integration
- Strong alignment with SBOM + EO 14028
- Lightweight for prototype scope

**Outputs usable for ML risk gate:**

- vulnerability count/severity
- affected packages
- risk scoring metadata

---

### Option B: OWASP ZAP (DAST for Web Applications)

**What it does:**

- Actively tests a running web application
- Detects XSS, injection, auth weaknesses

**Strengths:**

- True dynamic application testing

**Limitations:**

- Requires deployable staging environment
- Higher complexity for capstone prototype

---

### Option C: Nuclei (Template-Based Dynamic Scanning)

**What it does:**

- Runs vulnerability templates against targets

**Strengths:**

- Fast and modern
- Good for quick checks

**Limitations:**

- Less compliance/audit maturity than Trivy/ZAP

---
### Option D: Docker Scout (Supply Chain & Image Security)

**What it does:**

- Scans container images for vulnerabilities
- Provides SBOM visibility and dependency insights
- Tracks “what changed” between image versions
- Integrates directly with Docker ecosystem and Docker Hub

**Strengths:**

- Strong supply chain focus (built specifically for container provenance)
- Useful for monitoring vulnerabilities over time
- Developer-friendly output and remediation guidance

**Limitations:**

- More tightly coupled to Docker tooling/platform
- Some advanced features may require Docker Hub or paid tiers
- Less commonly used in academic CI/CD prototypes compared to Trivy

---

## 4. Recommended Approach

For the capstone prototype, the recommended dynamic scanning strategy is:

### Primary Dynamic Layer: Trivy Container/Image Scanning

Rationale:

- Directly supports supply chain integrity
- Integrates cleanly into CI/CD workflows
- Produces audit-friendly evidence
- Provides structured features for ML classification

### Secondary/Optional Enhancement: Docker Scout

Docker Scout provides additional supply chain intelligence, such as:

- Dependency change tracking across builds
- Developer-focused remediation insights

Scout may be evaluated as a supplementary tool if time permits.

### Future Enhancement: OWASP ZAP for Full DAST

ZAP can be included as an optional Phase 4 extension if time permits.

---

## 5. Integration Point in GitHub Actions (Draft)

Example pipeline step:

### Trivy Container/Image Scanning

```yaml
- name: Run Trivy Vulnerability Scan
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: myapp:latest
    format: json
    output: trivy-results.json
```

### Docker Scout Example (Optional)

```yaml
- name: Run Docker Scout Scan
  run: |
    docker scout quickview myapp:latest
    docker scout cves myapp:latest
```
