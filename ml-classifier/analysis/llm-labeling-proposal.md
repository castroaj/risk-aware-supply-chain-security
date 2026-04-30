# LLM-Assisted SBOM Labeling

## Why LLM Labeling Replaced Threshold Rules

The original labeling mechanism — `classify_metric_threshold` in `sbom_extractor.py` — applies fixed threshold checks against the `SecurityMetric` feature vector. This creates a fundamental ceiling: the Decision Tree is learning to reproduce a deterministic rule function rather than discovering latent security signal. High accuracy under threshold labeling measures "how well the DT approximated the threshold constants," not "how well it predicts actual supply chain risk."

Threshold rules also fire on only a subset of features independently. A holistic risk picture — where moderate `vuln_total`, an isolated `critical_cve_count`, and elevated `max_cvss` together warrant WARN even though no single value trips a threshold — cannot be expressed by a flat OR over independent cutoffs.

LLM labeling replaces this with an analyst-style reasoning pass over the full 8-feature vector:
- All features are considered jointly, not independently
- Vulnerability density relative to image size can be weighed
- The WARN class can capture genuinely intermediate risk rather than being a residue of threshold gaps
- Labels come with a justification, making labeling decisions auditable and reviewable by humans

---

## Current Implementation

**Labeler modes** — the `risk-classifier-label` CLI accepts `--labeler-mode llm` alongside the default `threshold` mode.

**Backends** — two backends are implemented in `src/classifier/backends/`:
- `GeminiBackend` — wraps `google-genai`; **preferred and used to generate current `data/labels/` CSVs**
- `AnthropicBackend` — wraps `anthropic` SDK; available as an alternative

Both backends use `temperature=0` to maximize label consistency across runs. Parse failures fall back to `WARN` with `confidence="low"` rather than crashing the labeling run — WARN is the safest fallback for a security gate: it flags the image for review without silently approving or hard-blocking it.

**System prompt** — loaded from a versioned file at `config/system-prompt-vN.md` and passed per invocation. Changing the prompt should produce a full re-labeling run and a new model version.

**Label persistence** — labels are frozen to CSV via `write_labels_csv` at labeling time. Training consumes the pre-labeled CSVs, not a live labeling call. This means:
- Prompt changes or threshold changes produce a visible `git diff` rather than silent drift
- Each committed label CSV is the ground truth for its corresponding model version

**Current default:**
```bash
make label-llm-gemini   # uses gemini-2.5-flash + config/system-prompt-v3.md
```

See `ml-classifier/CLAUDE.md` for full CLI reference.

---

## System Prompt Evolution

### v1 (`config/system-prompt-v1.md`) — used for model v0.0.5

The v1 prompt defined BLOCK as "one or more CRITICAL CVEs alongside systemic weakness breadth." In practice this fires on nearly every real-world production image with any critical CVE, since non-zero `top25_cwe_count` and `unique_cwe_count` accompany almost any critical finding. The result was 88% of images labeled BLOCK, with WARN restricted to images with zero critical CVEs — structurally eliminating the most operationally useful label for real-world images.

The v1 prompt was also missing:
- Any density or proportionality guidance (1 critical CVE in a 400-dep image treated identically to 1 in a 5-dep image)
- Operational framing (no indication that over-blocking is a failure mode)
- Numeric examples anchoring the WARN/BLOCK boundary

### v2 (`config/system-prompt-v2.md`) — used for model v0.0.6

Key changes from v1:
- **Concrete BLOCK anchors** — `critical_cve_count ≥ 5`, or `≥ 2 AND max_cvss = 10.0`, or density > 15% — replacing vague "elevated" language
- **Expanded WARN** — captures isolated critical CVEs in large images (1–4 criticals, low density), which v1 routed entirely to BLOCK
- **Density framing** — explicit guidance to weight findings by `total_dependency_count` before applying criteria
- **Operational framing** — BLOCK is labeled "rare"; over-blocking is named as a failure mode
- **Four calibrated examples** spanning the ALLOW/WARN/BLOCK spectrum with numeric justifications

Full v1 → v2 rationale and distribution comparison: `analysis/llm-labeling-evaluation-v1-vs-v2.md`

**Parse failures** fall back to `WARN` with `confidence="low"`. The `confidence` field is persisted in the label CSV and is available for post-labeling audit.

### v3 (`config/system-prompt-v3.md`) — current; used for model v0.0.7

Key changes from v2:

- **Density ratio as primary BLOCK signal** — explicit instruction to divide `top25_cwe_count` by `total_dependency_count`; ratio ≥ 1.0 is systemic compromise (BLOCK); < 0.3 suggests concentrated, not systemic, risk (WARN)
- **`max_cvss` de-weighted** — added explicit note that nearly all real-world images carry at least one 10.0 rating; `max_cvss` should not escalate WARN → BLOCK on its own, only support ALLOW when low
- **Pattern-based BLOCK/WARN/ALLOW archetypes** — replaced threshold-list guidance with narrative descriptions of what a BLOCK-level, WARN-level, and ALLOW-level image "looks like" holistically
- **ALLOW expanded to large images** — added Example 2 showing that a 118-component image with zero criticals and low breadth indicators is still ALLOW; v2 examples only covered minimal images for ALLOW
- **WARN/BLOCK boundary example at moderate density** — added Example 5 (9 criticals, 148 deps, `top25_cwe_count/total = 0.28`) explicitly labeled WARN to close the gap v2 identified as a P0 issue

**What is not implemented** — multi-pass majority voting and automatic confidence-gated review queues (proposed in the original draft of this document) have not been built. Manual spot-checking of the label CSV justification column is the current review mechanism. The `confidence` field in the CSV enables this without automated tooling.

---

## Outstanding Issues and Next Steps

| Priority | Issue | Approach |
|---|---|---|
| P0 | `aged-stale` bucket sources images that are too severely compromised for WARN | Replace with 1–2 year old moderate-CVE images |
| P0 | WARN/BLOCK boundary example gap in system prompt | ✅ *Resolved in v3* — Example 5 (9 criticals, 148 deps, density 0.28) explicitly labeled WARN |
| P1 | v2 absolute-count BLOCK anchors don't encode image size | ✅ *Resolved in v3* — density ratio (`top25_cwe_count / total_dependency_count`) added as primary BLOCK signal |
| P1 | Bucket-constrained labeling not enforced | Pass bucket name in user message; add prompt instruction restricting label range per bucket |
| P1 | ALLOW severely underrepresented (21 samples) | Add distroless, Chainguard, and recent minimal-footprint images |
| P2 | No held-out validation set | Carve 30-image stratified holdout before any training run |

Full per-version model analysis: `model-results/model-0.0.N/model-0.0.N-report.md`.
