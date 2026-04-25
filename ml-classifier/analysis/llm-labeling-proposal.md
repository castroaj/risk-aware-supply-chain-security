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

### Open Questions for Implementation

- **Prompt design**: The prompt must supply all 8 feature values, definitions, and label criteria in a structured, reproducible format. Output format must be machine-parseable (e.g., structured JSON with `label` and `justification` fields).
- **Model selection**: A capable reasoning model (e.g., Claude Sonnet or Opus) is preferred over a smaller model given the security-critical nature of the decision.
- **Consistency**: LLM outputs are non-deterministic. Running the labeler twice on the same SBOM could yield different labels. This is mitigated by label persistence (freeze on first run) but should be acknowledged.
- **Prompt versioning**: The prompt itself becomes a first-class artifact — changes to it should be versioned alongside the label CSVs so drift is always traceable.
- **Cost and rate limits**: Labeling a full training set of ~150+ images requires ~150+ API calls. Batching and retry logic are necessary for reliability.
