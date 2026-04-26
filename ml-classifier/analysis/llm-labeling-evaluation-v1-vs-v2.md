# LLM Labeling Evaluation: v1 System Prompt Analysis and v2 Rationale

## Overview

This document evaluates the quality of LLM-generated training labels produced by `gemini-2.5-flash` using `config/system-prompt-v1.md`. It compares the LLM label distribution against the threshold/rule-based labels (stored in `data/labels-orig/`) and identifies the root causes of distribution misalignment. It then documents the design decisions behind `config/system-prompt-v2.md`.

A retrospective section at the end of this document records a more fundamental finding that emerged after v2 labels were generated and model v0.0.6 was trained: the expected distribution targets in this document were themselves built on a flawed assumption — that bucket identity (high-qual / aged-stale / known-vuln) is a valid proxy for expected security label. The data shows it is not. Most production images, even well-maintained ones, do not merit an ALLOW label under strict security evaluation. This insight is a core design principle for all future labeling and model evaluation work.

---

## Label Distribution Comparison: v1 LLM vs. Threshold Labels

| Bucket | Source | ALLOW | WARN | BLOCK |
|---|---|---|---|---|
| **high-qual** | Threshold (`data/labels-orig/`) | 65.1% (112) | 25.0% (43) | 9.9% (17) |
| **high-qual** | LLM v1 (`data/labels/`) | 16.2% (28) | 10.4% (18) | **73.4% (127)** |
| **aged-stale** | Threshold (`data/labels-orig/`) | 17.5% (27) | 31.8% (49) | 50.6% (78) |
| **aged-stale** | LLM v1 (`data/labels/`) | 11.6% (18) | **88.4% (137)** | **0% (0)** |
| **known-vuln** | Threshold (`data/labels-orig/`) | 11.1% (5) | 26.7% (12) | 62.2% (28) |
| **known-vuln** | LLM v1 (`data/labels/`) | 2.2% (1) | 0.0% (0) | **97.8% (45)** |

The LLM output is dramatically polarized: it over-BLOCKs the high-qual bucket (73% vs. 10% expected) and collapses the aged-stale bucket entirely into WARN (88%) despite justifications in that CSV describing 44–97 critical CVEs at max_cvss 10.0.

---

## Qualitative Assessment: Did the LLM Follow the System Prompt?

**Structurally: yes.** The output format (JSON with `label`, `confidence`, `justification`) is consistently correct. Justifications always cite specific numeric feature values. Only one parse error occurred across ~374 images (httpd-2.4-alpine), indicating the response format guidance was effective.

**Semantically: partially.** The LLM correctly applied the v1 criterion that "one or more CRITICAL CVEs alongside systemic weakness breadth" → BLOCK. However, this criterion is so broad that it fires on nearly every real-world production image. The LLM was *correctly following the prompt* — the prompt itself was miscalibrated.

**The aged-stale anomaly is harder to explain.** Images in that bucket with 44–97 critical CVEs and max_cvss 10.0 unambiguously satisfy the v1 BLOCK criteria, yet 0 were labeled BLOCK. The justifications describe BLOCK-level findings but assign WARN. This may reflect an earlier labeling run with a different prompt draft, or external influence from the `bucket_label` column. Regardless, the v2 prompt should resolve this with explicit numeric anchors that make the BLOCK threshold unambiguous.

---

## Does the LLM Labeling Align with Project Objectives?

The project goal is a **GitHub Actions gating mechanism** that produces an ALLOW / WARN / BLOCK deployment decision with a full audit trail. Two properties are essential for this to function in practice:

1. **Developer trust**: If BLOCK fires on 73% of images from a curated "high quality" bucket, the pipeline becomes a friction generator. Engineers learn to override or ignore it, defeating the purpose entirely.
2. **Actionable signal distribution**: WARN is the most operationally valuable label — it says "fix this in the current sprint cycle." A classifier that rarely uses WARN (10% in high-qual, 0% in known-vuln) wastes the most useful escalation path.

**The v1 labels do not meet these objectives for the high-qual and aged-stale buckets.** The known-vuln bucket labeling is largely correct (intentionally vulnerable CTF/demo images should mostly be BLOCK).

---

## Root Cause Analysis

### 1. BLOCK bar is structurally too low

The v1 criterion reads:
> "One or more CRITICAL CVEs exist alongside systemic weakness breadth (elevated unique_cwe_count or top25_cwe_count)"

In practice, nearly every real-world image with any critical CVE also has a non-zero `top25_cwe_count` and `unique_cwe_count`. The phrase "one or more" means `critical_cve_count = 1` qualifies; "elevated" is undefined, so any non-zero value satisfies it. The result: BLOCK is the default outcome for any image with ≥ 1 critical CVE, which is a very large fraction of production images.

### 2. WARN is structurally squeezed out

The v1 WARN criterion requires *"no CRITICAL CVEs."* This means the decision tree is effectively:
- `critical_cve_count ≥ 1` → evaluate BLOCK only
- `critical_cve_count = 0` → evaluate WARN or ALLOW

There is no path to WARN for an image with 1–3 isolated critical CVEs in a 200-dependency image. This eliminates the most operationally important signal: *"urgent but not catastrophic — fix within a sprint."*

### 3. No density or proportionality awareness

A 400-component image with 1 critical CVE (density 0.25%) is fundamentally different from a 5-component image with 1 critical CVE (density 20%). The former is a single transitive dependency issue; the latter is a core compromise. V1 treats both identically because it operates only on raw counts, not rates.

### 4. Qualitative anchors are unresolvably vague

Terms like "non-trivial critical_cve_count," "systemic weakness breadth," and "elevated relative to total_dependency_count" have no numeric definition. Without anchors, an LLM defaults to the most conservative interpretation: 1 is non-trivial, any non-zero value is elevated, any CWE pattern is systemic.

### 5. BLOCK definition lacks operational framing

The v1 BLOCK definition ("must not be deployed without explicit security team approval and a remediation plan") is accurate but does not communicate that BLOCK is meant to be rare. Without a statement that over-blocking is a failure mode, the LLM optimizes for risk avoidance rather than signal precision.

---

## System Prompt v2 Design Decisions

### Decision 1 — Introduce vulnerability density as the primary evaluation lens

**Rationale:** Density (e.g., `critical_cve_count / total_dependency_count`) is the correct risk signal for heterogeneous images. A large, mature base image accumulates vulnerabilities in its transitive dependency tree; a minimal attack-surface image does not. Evaluating raw counts alone systematically penalizes larger, well-maintained images.

**Implementation:** Add a preamble paragraph to the Labeling Guidance section instructing the LLM to weight findings by `total_dependency_count` before applying the BLOCK/WARN/ALLOW criteria.

### Decision 2 — Replace vague BLOCK qualifiers with concrete numeric anchors

**Rationale:** Explicit thresholds eliminate the ambiguity that caused v1 to compress the distribution toward BLOCK.

**v2 BLOCK criteria:**
- `critical_cve_count ≥ 5` — multiple independent exploitable entry points, regardless of image size
- `critical_cve_count ≥ 2` AND `max_cvss = 10.0` — a trivially exploitable perfect-score CVE with additional criticals
- `critical_cve_count ≥ 1` AND density > 15% (`top25_cwe_count / total_dependency_count > 0.15`) — core attack surface dominated by known weaponized weakness classes
- Very high raw counts regardless of density: `critical_cve_count ≥ 10` OR `top25_cwe_count ≥ 50` — catches CTF/demo/intentionally-vulnerable images

### Decision 3 — Expand WARN to capture isolated critical CVEs

**Rationale:** A single critical CVE in a 200-component image is an urgent, fixable issue — not an emergency block. This is the most common real-world scenario and should drive sprint-cycle remediation workflows, not emergency approval chains.

**v2 WARN additions:**
- `critical_cve_count` 1–4 in a large image with low density (`critical_cve_count / total_dependency_count < 0.05`)
- `high_cve_count ≥ 8` OR `cvss_ge_7_count ≥ 10` without any critical CVEs — cluster of high-severity issues
- `max_cvss` 9.0–9.9 with `critical_cve_count = 0` — near-critical severity without criticals

### Decision 4 — Quantify ALLOW more precisely

**Rationale:** Clarifying ALLOW boundaries helps the LLM confidently assign ALLOW to clean images rather than second-guessing whether low-severity findings warrant a WARN escalation.

**v2 ALLOW criteria:**
- No CRITICAL CVEs, `high_cve_count ≤ 3`, `max_cvss < 7.0` (strict clean)
- No CRITICAL CVEs, `max_cvss < 9.0`, `top25_cwe_count ≤ 3`, `cvss_ge_7_count ≤ 4` (low-density moderate risk — acceptable)

### Decision 5 — Add operational framing to the label definitions

**Rationale:** The LLM must understand that precision is more valuable than conservatism. If it assigns BLOCK to 73% of images, it is not being "safe" — it is producing a non-functional classifier.

**v2 label definition additions:**
- BLOCK: *"Reserve BLOCK for images where deployment poses a genuine near-term security incident risk. BLOCK triggers an emergency remediation workflow; over-blocking erodes trust and defeats the pipeline's purpose."*
- WARN: *"Deployment may proceed under time-boxed conditions (e.g., a sprint-cycle fix window). WARN is the primary actionable signal for security-development collaboration."*

---

## Expected Distribution After v2

These targets are calibrated against the threshold labels as a reference. The threshold labels are a reasonable floor — the LLM should match them closely on the high-qual bucket and produce a more aggressive BLOCK distribution on aged-stale (which the threshold labels show should be ~50% BLOCK).

| Bucket | Target ALLOW | Target WARN | Target BLOCK |
|---|---|---|---|
| high-qual  | 50–65% | 25–35% | 5–15% |
| aged-stale | 15–20% | 40–55% | 25–40% |
| known-vuln |  5–12% | 10–20% | 70–85% |

> **Retrospective note:** These targets proved to be wrong. See the section below for why.

---

## What to Check After Relabeling

1. High-qual BLOCK rate drops from 73% to under 15%
2. Aged-stale BLOCK rate is non-zero (images with 44+ critical CVEs and max_cvss 10.0 should be BLOCK)
3. Justifications reference density reasoning when assigning WARN to images with isolated critical CVEs
4. The WARN label is the most common outcome across all three buckets in aggregate
5. `make train` on the new labels produces a well-distributed confusion matrix (not near-degenerate due to class collapse)

---

## Retrospective: The Bucket-Label Assumption Was the Flaw

After v2 labels were generated and model v0.0.6 was trained, the actual label distribution across all 371 images was: **ALLOW=21 (6%), WARN=100 (27%), BLOCK=250 (67%)**.

This is far from the expected 50–65% ALLOW in the high-qual bucket. The initial reaction was to treat this as a residual calibration failure in the v2 prompt. That interpretation was wrong. The data makes the correct interpretation clear.

### The Circular Reference in the Expected Targets

The "Expected Distribution After v2" table was calibrated against the threshold labels as a reference floor. But the threshold labels were themselves generated by a rule engine (`BLOCK_THRESHOLDS`, `WARN_THRESHOLDS`) that was deliberately tuned to produce a label distribution that *matched bucket identity*: high-qual images should mostly be ALLOW, aged-stale should mostly be WARN, known-vuln should mostly be BLOCK. The thresholds were set to reproduce that expectation.

The result is a circular reference:

1. Threshold constants were chosen to make high-qual → ALLOW
2. Expected distribution targets were set by treating those threshold labels as ground truth
3. The LLM was evaluated as "miscalibrated" for not reproducing those targets

At no point was the question asked: *do the feature values of high-qual images actually justify an ALLOW label by a strict security standard?*

### What the Feature Values Actually Say

The dataset statistics for the high-qual bucket (`dataset-statistics.md`) are unambiguous:

| Feature | Median |
|---|---|
| `critical_cve_count` | 3.0 |
| `max_cvss` | 10.0 |
| `vuln_total` | 51.0 |
| `cvss_ge_7_count` | 18.5 |

The **median** high-qual image has 3 critical CVEs and a CVSS 10.0 vulnerability somewhere in its dependency tree. The v2 BLOCK criterion `critical_cve_count ≥ 2 AND max_cvss = 10.0` fires on over half of the high-qual bucket by definition, regardless of how the prompt is worded. A 50–65% ALLOW rate for high-qual was never achievable without lowering the security bar below what the v2 criteria specify.

### The Harsh Truth: "High Quality" Does Not Mean "Secure"

The three buckets were assembled based on operational proxies for risk:

- **high-qual**: recently pushed, popular images from known maintainers — assumed to be well-patched
- **aged-stale**: older images, outdated base layers — assumed to have accumulated debt
- **known-vuln**: intentionally vulnerable images (CTF targets, demo apps) — assumed to be BLOCK

These proxies captured *maintenance posture*, not *security posture*. They are correlated but not equivalent. A popular, actively-maintained image is still a large image — it has a deep transitive dependency tree, many packages, and many surfaces for CVEs to accumulate. Popularity and maintenance frequency do not guarantee a clean vulnerability profile; they guarantee that *when* vulnerabilities are found, they are eventually patched. But "eventually" is not ALLOW.

**Most production container images — even well-maintained ones — do not meet a strict security analyst's threshold for unconditional deployment approval.** This is not a failure of the images or their maintainers; it reflects the nature of the modern software supply chain. A web server image pulling in OpenSSL, curl, zlib, and a dozen other system libraries will accumulate CVEs continuously, and patching lags behind disclosure.

The LLM, evaluating feature values without any knowledge of which bucket an image came from, arrived at this conclusion independently. When a strict security analyst sees `critical_cve_count=3, max_cvss=10.0`, the correct label is WARN or BLOCK — not ALLOW — regardless of the image's reputation or maintenance history. The LLM was right.

### What v0.0.6's ALLOW=6% Actually Means

The 21 ALLOW labels across 371 images (~6%) represent the images that genuinely have a clean-enough profile: no critical CVEs, low high-severity counts, max CVSS below 9.0. These are typically minimal base images (Alpine, distroless variants, scratch-based images) or tightly scoped utility images with few dependencies. In a real deployment gate, ALLOW should be rare and should mean something — an image that has earned unconditional clearance, not an image that received ALLOW because it was in the "good" bucket.

A classifier that outputs ALLOW 39% of the time (as v0.0.4 did, trained on threshold labels) is not safer — it is less precise. It is approving images with critical CVEs because the rule engine was calibrated to the bucket, not to the feature values.

### Implications for the Project

**1. WARN is the correct normal outcome.** For most production images in active use, WARN (deploy with a documented sprint-cycle fix window) is the operationally appropriate response. A pipeline that ALLOWs 6% of images, WARNs 27%, and BLOCKs 67% is functioning as a strict security gate. A pipeline that ALLOWs 39% is functioning as a rubber stamp.

**2. The bucket design is valid for data sourcing, not for label expectations.** The high-qual/aged-stale/known-vuln distinction was a useful heuristic for collecting a diverse training dataset across the risk spectrum. It was never valid as a prior on what the labels should be. Future dataset expansions should add images from each bucket without any expectation about what fraction will receive each label.

**3. The expected distribution targets should not be used as a calibration reference.** The table above is retained for historical context. Do not use it to evaluate whether a future prompt version is "well-calibrated." The correct check is whether the justifications in the label CSV are logically consistent with the feature values, not whether the distribution matches bucket identity.

**4. The v2 absolute-count BLOCK anchors carry a residual density problem.** The v2 criteria (`critical_cve_count ≥ 2 AND max_cvss = 10.0` → BLOCK) do not encode image size. A 400-dependency image with 2 critical CVEs and one CVSS 10.0 finding fires this criterion identically to a 5-dependency image with the same profile, despite representing very different risk densities. This is why many large, popular high-qual images end up BLOCK rather than WARN even under v2. A future v3 prompt should make the density lens structural rather than instructional — for example, by computing `critical_cve_count / total_dependency_count` as an explicit feature in the user message and anchoring thresholds on that rate.
