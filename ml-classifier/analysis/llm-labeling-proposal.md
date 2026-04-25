# LLM-Assisted SBOM Labeling Proposal

## Current Approach: Rule-Based Labeling and Its Limitations

The current labeling mechanism — `classify_metric` in `src/classifier/sbom_extractor.py` — applies a fixed set of threshold checks against the `SecurityMetric` feature vector to assign `ALLOW`, `WARN`, or `BLOCK` labels. These labels are then persisted to CSV files and consumed by the Decision Tree during training.

This creates a **circular dependency** between the labeler and the learner:

- `classify_metric` fires on only **4 of the 8 extracted features** — `critical_cve_count`, `top25_cwe_count`, `cvss_ge_7_count`, and `unique_cwe_count`. The remaining features (`total_dependency_count`, `vuln_total`, `high_cve_count`, `max_cvss`) are extracted into the feature vector but have **no influence on the training labels**.
- Because the DT trains exclusively against labels produced by `classify_metric`, it is learning to reproduce a deterministic rule function — not discovering latent security signal in the data.
- The model's accuracy ceiling is therefore **bounded by the correctness of the rule-based classifier**, not by the information content of the feature vector.
- High train/test accuracy in this setup measures "how well the DT approximated the thresholds," not "how accurately this predicts real supply chain risk."

The bucket curation (`high-qual`, `aged-stale`, `known-vuln`) does carry genuine external signal, since those populations were selected to represent real-world ALLOW/WARN/BLOCK candidates. But the label assigned within a bucket is still a function of `classify_metric` alone — a flat OR over independent threshold checks — which discards holistic interaction between features.

---

## Proposed Approach: LLM-Assisted Labeling with Justification

Instead of applying `classify_metric` to generate training labels, use a large language model (LLM) to analyze each image's extracted `SecurityMetric` feature vector and produce:

1. A structured label: `ALLOW`, `WARN`, or `BLOCK`
2. A verbose natural-language **justification** explaining the reasoning behind that label

### Why This Changes the Labeling Fundamentally

A threshold-based labeler evaluates each feature independently against a hard cutoff. An LLM labeler can reason holistically:

- It can weigh the **combination** of a moderately high `vuln_total`, a non-zero `critical_cve_count`, a high `top25_cwe_count`, and an elevated `max_cvss` together — a risk profile that might slip under every individual threshold but clearly warrants a `WARN`.
- It can apply **contextual judgment** — for example, a high `total_dependency_count` alone is low signal, but paired with zero patched vulnerabilities and known-exploited CWEs, it becomes a meaningful risk indicator.
- It uses **all 8 features** (and can accommodate future features without threshold recalibration), ensuring the DT trains on labels that reflect the full feature space.

### Scalability Argument

Human expert review of hundreds of SBOM scan results is expensive, slow, and does not scale to CI/CD pipelines. LLM inference is:

- **Faster** than human review by orders of magnitude
- **Cheaper** per label than a security analyst's time
- **Consistent** in applying the same reasoning framework across all scans
- **Auditable** — each label comes with a justification that can be reviewed, challenged, or overridden by a human

This positions LLM labeling as the scalable middle ground between brittle threshold rules and unscalable expert review.

### Label Persistence and Auditability

The existing label-freeze design (persisting to CSV via `write_labels_csv`) is **fully compatible** with LLM-generated labels. The label CSV would gain an additional `justification` column containing the LLM's reasoning. This means:

- Labels remain frozen at scan time — the LLM's decision does not silently change on re-run
- Threshold changes (or prompt changes) produce a visible `git diff` on the label CSV, making drift explicit and auditable
- Human reviewers can read the justification column to spot-check LLM reasoning without re-examining raw SBOM JSON

### What the Decision Tree Learns

With LLM-generated labels, the DT is no longer approximating a deterministic rule function. It is learning to generalize the reasoning of an LLM security analyst across the feature space. The resulting model:

- Uses **all 8 features** as meaningful inputs during training
- Captures **feature interaction patterns** that the LLM identified as significant
- Produces predictions grounded in security reasoning, not threshold arithmetic

---

## System Prompt Design

The system prompt plays the role that `BLOCK_THRESHOLDS` and `WARN_THRESHOLDS` play today — it encodes the labeling rubric. The difference is that it does so in natural language, allowing holistic reasoning rather than independent threshold checks.

### Proposed System Prompt

```
You are a supply chain security analyst responsible for classifying container images based on their vulnerability and dependency profiles. You will be given a structured feature vector extracted from a CycloneDX SBOM scan produced by Trivy.

Your task is to assign one of three deployment risk labels:
- ALLOW  — The image meets acceptable security standards and may be deployed.
- WARN   — The image has moderate risk. It should be reviewed before deployment and may require remediation.
- BLOCK  — The image has critical or systemic risk and must not be deployed without explicit security team approval and a remediation plan.

## Feature Definitions

Each feature vector contains exactly these fields:

| Feature               | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| total_dependency_count| Total number of software components declared in the SBOM                    |
| vuln_total            | Total number of vulnerabilities detected across all components              |
| critical_cve_count    | Number of CVEs rated CRITICAL severity (highest across all rating sources)  |
| high_cve_count        | Number of CVEs rated HIGH severity                                          |
| cvss_ge_7_count       | Number of vulnerabilities with a CVSS score >= 7.0                          |
| max_cvss              | Highest single CVSS score found in the scan                                 |
| unique_cwe_count      | Number of distinct CWE weakness types present                               |
| top25_cwe_count       | Number of vulnerabilities matching the MITRE CWE Top 25 (2025 list)        |

## Labeling Guidance

Evaluate the full feature vector holistically. Do not evaluate any single feature in isolation.

BLOCK when:
- One or more CRITICAL CVEs exist alongside systemic weakness breadth (elevated unique_cwe_count or top25_cwe_count), suggesting the image is broadly compromised, not just incidentally vulnerable.
- The max_cvss is near or at 10.0 and is accompanied by a non-trivial critical_cve_count, indicating a directly exploitable, high-impact vulnerability is present.
- The combination of vuln_total, high_cve_count, and top25_cwe_count together indicate a pattern of known, actively exploited weaknesses at scale.

WARN when:
- The image has no CRITICAL CVEs but has multiple HIGH CVEs or a non-trivial cvss_ge_7_count, suggesting actionable but not immediately catastrophic risk.
- The unique_cwe_count or top25_cwe_count is elevated relative to total_dependency_count, indicating a disproportionate weakness density.
- The max_cvss is in the 7.0–9.9 range without accompanying CRITICAL counts — the image is exploitable but may have mitigating factors.

ALLOW when:
- No CRITICAL CVEs are present, HIGH CVEs are minimal or absent, and max_cvss is below 7.0.
- Any vulnerabilities present are low-severity, low-density, and not part of the MITRE Top 25.

## Output Format

Respond only with a valid JSON object. Do not include any text outside the JSON block.

{
  "label": "ALLOW" | "WARN" | "BLOCK",
  "confidence": "high" | "medium" | "low",
  "justification": "<2–4 sentences explaining which features drove the decision and why they indicate this risk level>",
  "key_signals": ["<feature_name>: <value> — <one-line reason this was significant>", ...]
}

The justification must reference specific feature values from the input. Do not produce generic reasoning.
```

### Prompt Versioning

The system prompt is a first-class artifact. Each version should be tagged with a short hash or semantic version (`v1`, `v2`, etc.) and stored alongside label CSVs. When the prompt changes, labels should be regenerated and the diff committed — the same way threshold changes produce a visible `git diff` today.

---

## Efficient Inference: Keeping Tokens Minimal

The feature vector for a single image is small — 8 integer or float values. The risk is the user message growing expensive if SBOM JSON is passed raw. The design principle is: **extract features first, send only the structured vector to the LLM**.

### Message Structure Per Image

The system prompt is sent once per API call. The user message for each image is a compact JSON object — no raw SBOM, no CVE descriptions, no component lists:

```json
{
  "image": "alpine:3.18",
  "scan_file": "data/scans/high-qual/alpine-3.18.json",
  "features": {
    "total_dependency_count": 14,
    "vuln_total": 0,
    "critical_cve_count": 0,
    "high_cve_count": 0,
    "cvss_ge_7_count": 0,
    "max_cvss": 0.0,
    "unique_cwe_count": 0,
    "top25_cwe_count": 0
  }
}
```

This user message is approximately **80–120 tokens** regardless of how large the underlying SBOM is. The system prompt is ~600 tokens. Total per-call budget: **~700–750 tokens in, ~150–200 tokens out**. For 150 images that is roughly **130,000 input tokens and 30,000 output tokens** — well within a single labeling run budget using Claude Haiku or Sonnet.

### Batching Strategy

The Anthropic API does not natively support multi-image batching in a single call while maintaining per-image structured outputs. The recommended approach:

1. **Batch API**: Use the Anthropic Batch API (`/v1/messages/batches`) to submit all ~150 image requests in one batch job. This reduces per-request overhead and enables significant cost reduction (50% discount on batch pricing). The system prompt is identical across all requests — specify it once per request object in the batch.
2. **Parse and persist on completion**: When the batch job completes, iterate results, parse each JSON response, and write all labels + justifications to the label CSV in a single pass.
3. **Retry on parse failure**: If the JSON output is malformed for a given image, re-queue that image as a single synchronous call. Do not fail the entire batch.

### Token Explosion Risks to Avoid

- **Never pass raw SBOM JSON** to the LLM. CycloneDX files can be 50–500KB. Even summarized, raw vulnerability entries add thousands of tokens per image with no benefit over the feature vector.
- **Never ask the LLM to extract features**. Feature extraction is deterministic and already handled by `build_security_metric_from_sbom`. The LLM's job is classification and reasoning, not parsing.
- **Cap justification length** via the prompt instruction ("2–4 sentences"). Without this, verbose models will produce multi-paragraph responses that inflate output token costs across a large label run.

---

## Non-Determinism: Impacts on the Downstream Decision Tree

LLMs sample from a probability distribution at inference time. Even with identical inputs, the same prompt can yield different labels across runs. This has concrete consequences for a Decision Tree trained on LLM-generated labels.

### The Upsides of Non-Determinism

**Soft boundary encoding.** Rule-based classifiers draw hard lines — an image with `critical_cve_count = 49` is ALLOW and one with `critical_cve_count = 50` is BLOCK. An LLM labeler produces labels that naturally vary near ambiguous decision boundaries. When the DT trains on this data, those boundary images may receive different labels in different runs, which prevents the model from learning false precision at the edge of a threshold. The DT's learned boundary becomes a soft zone rather than a cliff — which is closer to true security risk, where no single feature definitively determines safety.

**Ensemble potential.** Non-determinism enables a legitimate ensembling strategy: run the labeler multiple times (e.g., 3–5 passes with different temperature settings or seeds), aggregate the resulting labels by majority vote, and use the vote distribution as a confidence signal. Images with unanimous labels (3/3 BLOCK) are high-confidence training examples. Images with split votes (2 WARN, 1 BLOCK) are genuinely ambiguous and warrant human review before being included in training data.

**Exploration of the label space.** A deterministic labeler will always produce the same label distribution. A non-deterministic labeler may, across runs, surface images that sit near class boundaries — providing richer signal about where the DT's decision surface should be uncertain.

### The Downsides of Non-Determinism

**Training set instability.** If labels are regenerated (e.g., after a prompt change), previously WARN images may flip to BLOCK or ALLOW. Without label persistence and diffing, this instability silently corrupts the training set and invalidates accuracy comparisons across model versions. The DT may show improved accuracy on a new run simply because the label distribution shifted, not because the model improved.

**Inconsistent boundary learning.** If two nearly identical images (same feature values, different scan file names) receive different labels in the same labeling run due to non-determinism, the DT will attempt to learn a decision boundary that separates them — and will fail, potentially inducing overfitting or arbitrary splits in the tree near those points.

**Reproducibility of model artifacts.** A model trained on deterministically-generated labels can be reproduced exactly from the label CSV. A model trained on LLM-generated labels can only be reproduced if the label CSV is committed and the prompt is versioned. Without both, model-0.0.N is effectively irreproducible.

### Mitigation Strategies

**Temperature = 0 as the baseline.** Claude and most frontier models support setting `temperature=0`, which maximizes output determinism by always sampling the highest-probability token. This does not eliminate non-determinism entirely (the model's internal state can still vary across API versions and infrastructure), but it dramatically reduces label variance for clear-cut cases. Use `temperature=0` for all labeling runs.

**Confidence gating.** The system prompt requests a `confidence` field (`high`, `medium`, `low`). Images labeled with `low` confidence are not automatically included in the training CSV — they are written to a separate review queue. A human (or a second-pass LLM call with an extended prompt) resolves these before the label is committed. This preserves the scalability benefit while preventing ambiguous labels from polluting the training set.

**Multi-pass majority voting for ambiguous images.** For any image where `confidence` is not `high`, run 3 independent inference calls (each with `temperature=0` but submitted as separate requests to account for API-level non-determinism). Accept the majority label. If all three disagree, flag the image for human review.

**Prompt stability as a contract.** Treat the system prompt as immutable for a given model version. Changes to the prompt trigger a full re-labeling run, a new label CSV commit, and a new model version — the same way threshold changes do today. This makes non-determinism a controlled, auditable event rather than a hidden source of drift.

**Label CSV as the source of truth.** The existing freeze-at-scan-time design directly combats non-determinism at the system level. Once a label is written to CSV and committed, it does not change unless a human or a deliberate re-labeling run changes it. The LLM's non-determinism is a property of the labeling step, not of the training step — and the CSV decouples the two.
