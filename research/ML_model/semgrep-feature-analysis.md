# Semgrep Feature Value Analysis: `semgrep_total` and `semgrep_high_count`

> **Status (2026-03-21):** Based on the analysis in Section 6, `semgrep_total` and
> `semgrep_high_count` have been **removed** from the `SecurityMetric` feature vector,
> `sbom_extractor.py`, and all associated documentation. The feature count is now 9.
> This document serves as the rationale record for that decision. SAST integration
> remains valid for a future first-party pipeline scope (Use Case B).

## 1. Background

`semgrep_total` and `semgrep_high_count` are two of the eleven features in the `SecurityMetric` feature vector, defined in `feature-extraction.md` as follows:

**`semgrep_total`** — the total count of issues matched by the Semgrep engine against the source code, aggregating all static analysis findings including security hotspots, correctness issues, and performance anti-patterns. Derived from the length of the `.results` JSON array in Semgrep output. A high count serves as a proxy for technical debt and poor code quality.

**`semgrep_high_count`** — the number of Semgrep findings assigned the highest severity level (`ERROR`). These findings correspond to known bad patterns that produce vulnerabilities such as SQL injection, XSS, and hardcoded credentials. A non-zero count signals explicit application-layer security defects requiring remediation before deployment.

These features were designed to capture a distinct risk class: **application-layer coding defects**. This is a class of vulnerability that none of the other eight features address. The vulnerability scan features (`critical_cve_count`, `cvss_ge_7_count`, `top25_cwe_count`, etc.) report on CVEs in third-party packages and libraries. None of these detect SQL injection written by the developer, hardcoded credentials in application code, or XSS introduced in the application layer. SAST is the only feature category that does.

Both `classification-proposal.md` and `training-data-generation-plan.md` treat these features as active discriminators within the pipeline architecture. The classification pseudocode in `classification-proposal.md` (Section XII) includes both:

```python
if (
    ...
    semgrep_high_count > ALLOWABLE_SEMGREP_HIGH_COUNT
    ):
    return "BLOCK"
elif (
    ...
    semgrep_total >= ALLOWABLE_SEMGREP_COUNT
   ):
    return "WARN"
```

The labeling rubric pseudocode in `training-data-generation-plan.md` (Section IV) reproduces the same logic. Both documents present SAST as a first-class discriminator contributing to both BLOCK and WARN decisions.

---

## 2. Current Status: The Zero-Variance Problem

The computed statistics across all three training buckets (143 images total) show:

### high-qual (ALLOW) — n = 57

| Feature | min | median | mean | max |
|---|---|---|---|---|
| `semgrep_total` | 0.0 | 0.0 | 0.0 | 0.0 |
| `semgrep_high_count` | 0.0 | 0.0 | 0.0 | 0.0 |

### aged-stale (WARN) — n = 55

| Feature | min | median | mean | max |
|---|---|---|---|---|
| `semgrep_total` | 0.0 | 0.0 | 0.0 | 0.0 |
| `semgrep_high_count` | 0.0 | 0.0 | 0.0 | 0.0 |

### known-vuln (BLOCK) — n = 31

| Feature | min | median | mean | max |
|---|---|---|---|---|
| `semgrep_total` | 0.0 | 0.0 | 0.0 | 0.0 |
| `semgrep_high_count` | 0.0 | 0.0 | 0.0 | 0.0 |

Variance = 0.0 across every bucket, every statistic.

### Structural Cause

This is not a code bug or a configuration gap. Semgrep is a source-code analysis tool. It requires access to source files — `.py`, `.js`, `.go`, `.java`, etc. — to perform pattern matching and taint analysis. The current pipeline evaluates **pre-built public Docker images pulled from Docker Hub**. Source code is unavailable for any of the 143 training images.

This is a **categorical scope mismatch**, not a resolvable implementation gap. No amount of improvement to `sbom_extractor.py` or the scanning pipeline can produce non-zero Semgrep values for pre-built container images without first acquiring the matching source code.

### Consequences

**Zero information gain for Decision Tree training.** A feature with variance 0.0 produces zero information gain under any split criterion (Gini, entropy, information gain ratio). The Decision Tree algorithm cannot create any split on this feature — it will never appear in a learned tree. Including it in the training matrix wastes a column and imposes a small but unnecessary compute cost during `fit()`.

**Rubric conditions are permanently unreachable.** The BLOCK condition `semgrep_high_count > ALLOWABLE_SEMGREP_HIGH_COUNT` and the WARN condition `semgrep_total >= ALLOWABLE_SEMGREP_COUNT` from the classification pseudocode can never fire on the current dataset. Any threshold greater than zero is unreachable; a threshold of zero would flag every image identically and add no discriminating value.

**Honesty and transparency defect for compliance auditing.** The feature schema in the output CSV and JSON has no way to distinguish between two distinct states: (a) SAST was performed and found zero findings, and (b) SAST was never performed. Both states produce the same output: `semgrep_total=0.0, semgrep_high_count=0.0`. For any compliance auditor relying on artifact output to verify that security scanning was performed — consistent with NIST SSDF practice PW.8 (Integrate Security Testing into the Development and Built Process) — a column of zeros implies coverage that does not exist. This is an audit trail integrity problem.

---

## 3. The Case FOR Value

**Theoretically sound.** SAST captures a risk class that is structurally orthogonal to CVE/SBOM features. An image could have zero CVEs (clean dependency tree, recently updated) while its application layer contains a SQL injection vulnerability or a hardcoded API key. No other feature in the vector would catch this. The design rationale in `feature-extraction.md` is correct.

**Architecturally committed.** SAST is embedded in the pipeline flow (`classification-proposal.md`, Section II: step 5), the feature vector definition (`feature-extraction.md`), the classification pseudocode (`classification-proposal.md`, Section XII), and the labeling rubric (`training-data-generation-plan.md`, Section IV). Removing it would create divergence between the implemented schema and the documented architecture.

**Applicable for first-party builds.** When the pipeline evaluates an internally developed container image — the primary Use Case B scenario — source code is available in the repository at build time. In that context, these features would have real discriminating power. A developer pushing a new service with a hardcoded credential (`semgrep_high_count > 0`) should receive a BLOCK regardless of clean vulnerability scans.

**Schema stability.** The CSV and JSON column positions are consumed by downstream tools and any future ML training scripts. Removing columns mid-project requires coordinated changes across consumers and invalidates previously generated CSVs.

---

## 4. The Case AGAINST (in Current Scope)

**Mathematically useless as ML inputs.** Variance = 0.0 across all 143 samples and all 3 label buckets. These features carry no signal and cannot contribute to any learned Decision Tree split. Including them in `X_train` is equivalent to training on a column of constants.

**False audit signal.** A compliance auditor reviewing an output artifact cannot distinguish "SAST ran and found nothing" from "SAST was never invoked." Both look identical in the current schema. This distinction is critical for NIST SSDF compliance documentation claims: producing artifacts that imply coverage not provided is an audit integrity failure.

**Scope mismatch is categorical, not temporary.** Third-party public images have no source code access by design. This is not an implementation deficit that will be resolved in a future sprint — it is a fundamental constraint of evaluating pre-built binary artifacts. The mismatch persists for the entire 143-image dataset and for any future dataset that follows the same acquisition strategy.

**Training contamination risk.** If the model is later retrained on a mixed dataset — some images with real SAST signals, some without — without explicitly excluding or flagging the zero-scan rows, the structurally zero-valued training history could bias the learned feature weights. A tree trained on data where `semgrep_high_count` is always 0 may assign it low importance even when real SAST signals are introduced, depending on retraining strategy.

---

## 5. Scope Clarification: Two Distinct Use Cases

The confusion in the literature arises because the project architecture spans two scenarios that make fundamentally different assumptions about source code availability.

**Use Case A — Third-party image evaluation** (current scope): Input is a pre-built container image pulled from a public registry. Source code is not available. SBOM and vulnerability data are extracted from the binary artifact. SAST is architecturally inapplicable. The 143-image training dataset, all feature statistics, the rule-based thresholds in `sbom_extractor.py`, and all three image list CSVs are entirely Use Case A.

**Use Case B — First-party build pipeline** (future scope): Input is developer source code being containerized as part of an internal CI/CD workflow. Source code is present in the repository. SAST is applicable and valuable. The pipeline design in `classification-proposal.md` (Section II) describes this scenario: "Developer pushes code → Build and unit tests → SBOM generation → Vulnerability scanning → SAST scanning."

`SAST_Data_Analysis.md` reasons about SAST integration from a Use Case B perspective — the conclusions in that document are correct within that context, but do not transfer to Use Case A. The source code availability assumption that underlies every argument in that paper does not hold for the training dataset or the current pipeline scope.

## 6. Approaches for Acquiring Source Code for the Existing Dataset

Two concrete strategies exist for acquiring version-matched source code for the 143 images already in the dataset. Both must contend with the central difficulty: automatically matching the exact source code version that produced a given published image.

### Approach 1 — OCI Label Extraction (SHA-Pinned)

Many container images embed OCI-standard labels encoding the exact source repository and git commit used to build them. The relevant labels are:
- `org.opencontainers.image.source` — URL of the source Git repository
- `org.opencontainers.image.revision` — the exact git commit SHA

These labels are present in the SBOM's `.metadata.component.properties` array. The extension would be:

1. Extract `org.opencontainers.image.source` and `org.opencontainers.image.revision` from the SBOM metadata
2. Clone the repository and check out the exact SHA (`git clone` followed by `git checkout <sha>`; `--depth 1` is insufficient)
3. Run `semgrep --config=auto` on the cloned tree
4. Parse output and extract `semgrep_total` / `semgrep_high_count`

**Strengths:** Fully automatable using the already-parsed SBOM. SHA-pinned checkout provides the exact code snapshot that produced the image — the best possible version match.

**Weaknesses:** Coverage is incomplete. Many images in the dataset (especially aged-stale and known-vuln buckets) predate the OCI annotation standard or were built by maintainers who do not set these labels. Where labels are absent, the approach degrades to the same zero-value problem. Some images also embed incorrect or outdated revision labels (e.g., the label reflects the Dockerfile repo, not the upstream application source).

### Approach 2 — Tag-Based GitHub Mapping (Semi-Automated)

For well-known official images (e.g., `nginx:1.25.3`, `python:3.11-slim`), a curated mapping table from image name to GitHub repository can be maintained alongside the existing CSV image lists. The process:

1. For each image in `image-lists/*.csv`, record the corresponding GitHub source repository in an additional column
2. Parse the image tag and attempt to resolve it to a matching Git tag in the repository
3. Clone at that tag and run Semgrep

**Strengths:** Works well for the high-qual bucket, which predominantly contains well-maintained official images with documented GitHub sources and consistent tag naming. The mapping table is a one-time investment maintainable alongside the image lists.

**Weaknesses:** Requires manual curation — not fully automatable. Tag naming conventions diverge (Docker Hub `nginx:1.25.3` may correspond to a Git tag of `1.25.3`, `v1.25.3`, `release-1.25.3`, or a commit SHA with no matching tag at all). The aged-stale and known-vuln buckets contain more obscure or unofficial images where a source repo may not exist or may not be publicly accessible. For images that have since been deleted from Docker Hub or whose source repos have been archived, reconstruction is not guaranteed.

### Assessment

Neither approach fully automates version-matched source acquisition for the complete 143-image dataset. Approach 1 provides a deterministic solution where OCI labels exist and should be attempted first. Approach 2 fills the gap for popular official images that lack annotations. A combined strategy — attempt OCI label extraction first, fall back to the curated mapping table — would maximize coverage while remaining automatable for the label-bearing subset.

Even with both approaches combined, some fraction of the dataset (likely concentrated in the aged-stale and known-vuln buckets) will remain without matched source code. The zero-variance problem cannot be fully eliminated retroactively for the current 143-image training set.