# ML Training Data Generation

- [ML Training Data Generation](#ml-training-data-generation)
  - [I. Purpose and Scope](#i-purpose-and-scope)
  - [II. Data Sourcing Strategy](#ii-data-sourcing-strategy)
  - [III. Automated Pipeline Execution](#iii-automated-pipeline-execution)
  - [IV. Labeling Rubric](#iv-labeling-rubric)
    - [Option 1: Programmatic Label](#option-1-programmatic-label)
    - [Option 2: Manual Process](#option-2-manual-process)
  - [V. Artifact Storage](#v-artifact-storage)

## I. Purpose and Scope

This aims to define the methodology for generating a robust and effective training set for the decision tree classifier.
Due to a strategically custom feature vector, the system will need a systematic way to generate its own training set.

## II. Data Sourcing Strategy

To ensure a diverse dataset that prevents model overfitting but still realizes relevant features for classification, the 
training process will source targets 

The target list will need to include three core categories to ensure balanced class distribution:

1. **High-Quality/Well Maintained**: Official and certified images that will easily satisfy criteria for the `ALLOW` class
2. **Aged/Stale**: Images that are out-of-date within a 6-month to 2-Year window in order to capture natural vulnerability accumulation, likely populating either any of the three categories, but typically `WARN` or `BLOCK`
3. **Known/Vulnerable**: Images with known vulnerabilities that should guarantee strong signals for the `BLOCK` class


## III. Automated Pipeline Execution

The data generation process will mirror what the production actions workflow. A standalone automation script will process the target list through the following sequential stages:

1. **Asset Acquisition**:
   - Pull the specified container image by the image tag from a reputable mirror (i.e. DockerHub)
   - Clone the exact git commit/tag of the source repository corresponding to that image.
2. **Generate Scanning Artifacts**:
   - Runs a trivy scan for SBOM/Vulnerability data on open source image
   - Runs SemGrep on open-source software *(deferred — SAST is out of scope for the current Use Case A pipeline; see `research/ML_model/semgrep-feature-analysis.md`)*
3. **Feature Extraction**:
   - Parse the artifacts from the scanning phase into a structured feature vector identified by its source artifacts
4. **Labeling**:
   - Either a manual or automated labeling of the feature vector must be done via agreed upon [Labeling Rubric](./training-data-generation-plan.md#iv-labeling-rubric)

## IV. Labeling Rubric

### Option 1: Programmatic Label

An agreed upon labeling rubric could be applied to the feature vector in order to automate the training data:

```python
if (
    critical_cve_count > MIN_ALLOWABLE_CRITICAL_CVE or \
    max_cvss >= MAX_ALLOWABLE_CVSS or \
    (high_cve_count >= MIN_ALLOWABLE_HIGH_CVE_COUNT and fix_available_count >= MIN_ALLOWABLE_FIX_AVAILABLE_COUNT) or \
    semgrep_high_count > ALLOWABLE_SEMGREP_HIGH_COUNT
    ):
    return "BLOCK"
elif (
    high_cve_count in ALLOWABLE_HIGH_CVE_RANGE or \
    cvss_ge_7_count >= ALLOWABLE_CVSS_GE_7_COUNT or \
    semgrep_total >= ALLOWABLE_SEMGREP_COUNT
   ):
    return "WARN"
else:
    return "ALLOW"
```

> NOTE: While this approach is far more efficient and will allow the team to annotate far more data sets, it is likely not as robust as a human's conclusive decision

### Option 2: Manual Process

A team member manually reviews the artifact results and selects a classification label

> NOTE: This is very effective, but very time intensive and likely will not scale to what we need

## V. Artifact Storage

To be consistent with the system's auditability requirements, all data generated for the training set will also
be retained. This ensure's traceable decision process during the training process. For each harvested target, the 
pipeline will store:

- SBOM/Vulnerability Scan (produced by [`aquasecurity/trivy`](https://github.com/aquasecurity/trivy))
- SemGrep Scan (produced by [`semgrep/semgrep`](https://github.com/semgrep/semgrep))
- The extracted, normalized feature vector
- Label applied to the feature vector (`ALLOW`, `WARN` ,`BLOCK`)