# Training Set Dataset Statistics

Statistics computed from the three classification buckets used to calibrate the
rule-based rubric in `sbom_extractor.py`.  All values are rounded to one decimal
place.  `n` is the number of scanned images per bucket.

These statistics were computed at the time the label CSVs in `data/labels/` were generated.

---

## Per-Feature Statistics

### high-qual (ALLOW) — n = 172

| Feature | min | median | mean | max |
|---|---|---|---|---|
| `total_dependency_count` | 0.0 | 118.5 | 198.5 | 3141.0 |
| `vuln_total` | 0.0 | 51.0 | 303.9 | 4734.0 |
| `critical_cve_count` | 0.0 | 3.0 | 6.2 | 57.0 |
| `high_cve_count` | 0.0 | 29.0 | 202.8 | 3553.0 |
| `cvss_ge_7_count` | 0.0 | 18.5 | 83.2 | 1253.0 |
| `max_cvss` | 0.0 | 10.0 | 9.0 | 10.0 |
| `unique_cwe_count` | 0.0 | 25.0 | 37.0 | 145.0 |
| `top25_cwe_count` | 0.0 | 16.0 | 101.7 | 1678.0 |

### aged-stale (WARN) — n = 154

| Feature | min | median | mean | max |
|---|---|---|---|---|
| `total_dependency_count` | 0.0 | 177.0 | 299.8 | 2313.0 |
| `vuln_total` | 0.0 | 333.0 | 1195.2 | 7123.0 |
| `critical_cve_count` | 0.0 | 38.0 | 38.8 | 112.0 |
| `high_cve_count` | 0.0 | 218.5 | 809.5 | 4494.0 |
| `cvss_ge_7_count` | 0.0 | 177.5 | 413.2 | 2003.0 |
| `max_cvss` | 0.0 | 10.0 | 9.5 | 10.0 |
| `unique_cwe_count` | 0.0 | 89.0 | 91.3 | 199.0 |
| `top25_cwe_count` | 0.0 | 141.0 | 485.1 | 2666.0 |

### known-vuln (BLOCK) — n = 45

| Feature | min | median | mean | max |
|---|---|---|---|---|
| `total_dependency_count` | 77.0 | 272.0 | 468.1 | 2280.0 |
| `vuln_total` | 0.0 | 412.0 | 457.1 | 1571.0 |
| `critical_cve_count` | 0.0 | 57.0 | 60.0 | 144.0 |
| `high_cve_count` | 0.0 | 275.0 | 315.2 | 1188.0 |
| `cvss_ge_7_count` | 0.0 | 249.0 | 247.9 | 701.0 |
| `max_cvss` | 0.0 | 10.0 | 9.8 | 10.0 |
| `unique_cwe_count` | 0.0 | 79.0 | 79.9 | 161.0 |
| `top25_cwe_count` | 0.0 | 168.0 | 216.1 | 779.0 |

---

## Feature Rubric Rationale

### Included in rubric

| Feature | Tiers | Reason included |
|---|---|---|
| `critical_cve_count` | BLOCK ≥ 50, WARN ≥ 10 | Strong discriminator across all three buckets (medians: 3 / 38 / 57). Semantically unambiguous — a critical CVE is directly exploitable with no authentication in the worst case. |
| `cvss_ge_7_count` | WARN ≥ 100 | Captures the volume of high-severity issues (CVSS ≥ 7). Medians 18.5 / 177.5 / 249.0 give clean ALLOW vs. WARN separation. Not used for BLOCK because `critical_cve_count` already handles the BLOCK-level signal with more specificity. |
| `unique_cwe_count` | WARN ≥ 40 | A broad spread of distinct weakness categories signals systemic developer mistakes rather than a few unpatched packages. WARN-only: the BLOCK bucket (median=79) is *lower* than WARN (median=89) because intentionally-vulnerable apps tend to concentrate a narrow set of well-known exploitable CWEs, while aged-stale images accumulate wider variety. Threshold of 40 sits between the ALLOW median (25) and WARN median (89). |
| `top25_cwe_count` | BLOCK ≥ 150, WARN ≥ 50 | Counts findings that map to MITRE Top 25 most dangerous CWEs — directly captures the "many small bugs, no criticals" failure mode. An image with 100+ Top-25-CWE hits but zero critical CVEs still represents systematically poor code quality that should not receive ALLOW. Medians 16 / 141 / 168 give clean thresholds at both tiers. |

### Excluded from rubric

| Feature | Reason excluded |
|---|---|
| `total_dependency_count` | Reflects image size, not security posture. Medians 118.5 / 177 / 272 track complexity rather than risk; a large well-maintained image would be unfairly penalized. |
| `vuln_total` | High correlation with `critical_cve_count`. Dominated by low/medium-severity findings. Using both double-counts the same underlying risk; `critical_cve_count` is more specific. |
| `high_cve_count` | Correlated with both `critical_cve_count` and `cvss_ge_7_count`. Adding it would cause false WARN promotions for high-qual images without adding orthogonal signal. |
| `max_cvss` | Near-useless discriminator: all three bucket medians are 10.0. A single unpatched critical CVE anywhere pushes this to maximum. Cannot distinguish one critical CVE from 500. |

---

## Threshold Recommendations

The following constants are implemented in `sbom_extractor.py` as
`BLOCK_THRESHOLDS` and `WARN_THRESHOLDS`.  BLOCK is evaluated before WARN; any
single breach triggers that verdict level.

### BLOCK thresholds

| Feature | Threshold | Derivation |
|---|---|---|
| `critical_cve_count` | ≥ 50 | Sits between WARN median (38) and BLOCK median (57). |
| `top25_cwe_count` | ≥ 150 | Sits between WARN median (141) and BLOCK median (168); catches images with systemic high-danger weaknesses even when critical CVE count is low. |

### WARN thresholds

| Feature | Threshold | Derivation |
|---|---|---|
| `critical_cve_count` | ≥ 10 | Sits between ALLOW median (3) and WARN median (38); catches images that have accumulated double-digit critical CVEs without yet breaching the BLOCK tier. |
| `cvss_ge_7_count` | ≥ 100 | Sits between ALLOW median (18.5) and WARN median (177.5); flags high-volume high-severity issue accumulation. |
| `unique_cwe_count` | ≥ 40 | Sits between ALLOW median (25) and WARN median (89); captures broad attack-surface diversity without triggering on a few isolated weaknesses. |
| `top25_cwe_count` | ≥ 50 | Sits between ALLOW median (16) and WARN median (141); catches images with a meaningful concentration of top-25-dangerous findings. |

---

## Observed Classification Distribution

| Bucket | ALLOW | WARN | BLOCK | Total |
|---|---|---|---|---|
| high-qual | 110 | 45 | 17 | 172 |
| aged-stale | 23 | 53 | 78 | 154 |
| known-vuln | 3 | 14 | 28 | 45 |

The 17 BLOCK results in high-qual are images with high `top25_cwe_count` or `critical_cve_count`; review of those scans confirms they are genuinely higher-risk than the median of that bucket. The 23 ALLOW results in aged-stale reflect images sourced from that bucket that have low overall CVE counts and fall below all WARN thresholds despite their age.
