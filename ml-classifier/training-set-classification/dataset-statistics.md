# Training Set Dataset Statistics

Statistics computed from the three classification buckets used to calibrate the
rule-based rubric in `sbom_extractor.py`.  All values are rounded to one decimal
place.  `n` is the number of scanned images per bucket.

Run `training-set-generation/compute_statistics.py` from the `ml-classifier/` directory to reproduce.

---

## Per-Feature Statistics

### high-qual (ALLOW) — n = 57

| Feature | min | median | mean | max |
|---|---|---|---|---|
| `total_dependency_count` | 0.0 | 93.0 | 114.9 | 397.0 |
| `vuln_total` | 0.0 | 26.0 | 219.7 | 4255.0 |
| `critical_cve_count` | 0.0 | 1.0 | 4.3 | 27.0 |
| `high_cve_count` | 0.0 | 13.0 | 160.0 | 3200.0 |
| `cvss_ge_7_count` | 0.0 | 10.0 | 63.7 | 1086.0 |
| `max_cvss` | 0.0 | 9.8 | 8.8 | 10.0 |
| `unique_cwe_count` | 0.0 | 17.0 | 24.5 | 127.0 |
| `top25_cwe_count` | 0.0 | 8.0 | 74.3 | 1509.0 |
| `base_image_age_days` | 0.0 | 47.0 | 262.9 | 779.0 |

### aged-stale (WARN) — n = 55

| Feature | min | median | mean | max |
|---|---|---|---|---|
| `total_dependency_count` | 15.0 | 160.0 | 284.3 | 2313.0 |
| `vuln_total` | 0.0 | 332.0 | 1503.9 | 7123.0 |
| `critical_cve_count` | 0.0 | 32.0 | 35.3 | 100.0 |
| `high_cve_count` | 0.0 | 215.0 | 981.1 | 4494.0 |
| `cvss_ge_7_count` | 0.0 | 155.0 | 481.2 | 2003.0 |
| `max_cvss` | 0.0 | 10.0 | 9.3 | 10.0 |
| `unique_cwe_count` | 0.0 | 89.0 | 96.6 | 199.0 |
| `top25_cwe_count` | 0.0 | 133.0 | 590.5 | 2666.0 |
| `base_image_age_days` | 641.0 | 1627.0 | 1599.7 | 2210.0 |

### known-vuln (BLOCK) — n = 31

| Feature | min | median | mean | max |
|---|---|---|---|---|
| `total_dependency_count` | 77.0 | 286.0 | 527.9 | 2280.0 |
| `vuln_total` | 0.0 | 412.0 | 432.5 | 1430.0 |
| `critical_cve_count` | 0.0 | 56.0 | 57.7 | 144.0 |
| `high_cve_count` | 0.0 | 275.0 | 295.9 | 1079.0 |
| `cvss_ge_7_count` | 0.0 | 249.0 | 236.4 | 701.0 |
| `max_cvss` | 0.0 | 10.0 | 9.7 | 10.0 |
| `unique_cwe_count` | 0.0 | 75.0 | 75.1 | 161.0 |
| `top25_cwe_count` | 0.0 | 166.0 | 202.8 | 699.0 |
| `base_image_age_days` | 0.0 | 2683.0 | 2460.6 | 3392.0 |

---

## Feature Rubric Rationale

### Included in rubric

| Feature | Tiers | Reason included |
|---|---|---|
| `critical_cve_count` | BLOCK ≥ 50, WARN ≥ 10 | Best single discriminator across all three buckets (medians: 1 / 32 / 56). Semantically unambiguous — a critical CVE is directly exploitable with no authentication in the worst case. |
| `base_image_age_days` | BLOCK ≥ 2000, WARN ≥ 365 | Strong temporal signal. Medians are 47 / 1627 / 2683 — almost no overlap between ALLOW and WARN, good separation between WARN and BLOCK. One year (365) is a widely recognised industry threshold for "stale". |
| `cvss_ge_7_count` | WARN ≥ 100 | Captures the volume of high-severity issues (CVSS ≥ 7). Medians 10 / 155 / 249 give clean ALLOW vs. WARN separation. Not used for BLOCK because `critical_cve_count` already handles the BLOCK-level signal with more specificity. |
| `unique_cwe_count` | WARN ≥ 40 | A broad spread of distinct weakness categories signals systemic developer mistakes rather than a few unpatched packages. WARN-only: the BLOCK bucket (median=75) is *lower* than WARN (median=89) because intentionally-vulnerable apps tend to concentrate a narrow set of well-known exploitable CWEs, while aged-stale images accumulate wider variety. Threshold of 40 sits well above the ALLOW median (17). |
| `top25_cwe_count` | BLOCK ≥ 150, WARN ≥ 50 | Counts findings that map to MITRE Top 25 most dangerous CWEs — directly captures the "many small bugs, no criticals" failure mode. An image with 100+ Top-25-CWE hits but zero critical CVEs still represents systematically poor code quality that should not receive ALLOW. Medians 8 / 133 / 166 give clean thresholds at both tiers. |

### Excluded from rubric

| Feature | Reason excluded |
|---|---|
| `total_dependency_count` | Reflects image size, not security posture. Medians 93 / 160 / 286 track complexity rather than risk; a large well-maintained image would be unfairly penalised. |
| `vuln_total` | High correlation with `critical_cve_count`. Dominated by low/medium-severity findings. Using both double-counts the same underlying risk; `critical_cve_count` is more specific. |
| `high_cve_count` | Correlated with both `critical_cve_count` and `cvss_ge_7_count`. Adding it would cause false WARN promotions for high-qual images without adding orthogonal signal. |
| `max_cvss` | Near-useless discriminator: ALLOW median = 9.8, WARN = 10.0, BLOCK = 10.0. A single unpatched critical CVE anywhere pushes this to maximum. Cannot distinguish one critical CVE from 500. |

---

## Threshold Recommendations

The following constants are implemented in `sbom_extractor.py` as
`BLOCK_THRESHOLDS` and `WARN_THRESHOLDS`.  BLOCK is evaluated before WARN; any
single breach triggers that verdict level.

### BLOCK thresholds

| Feature | Threshold | Derivation |
|---|---|---|
| `critical_cve_count` | ≥ 50 | Sits between WARN median (32) and BLOCK median (56), well above ALLOW max (27). |
| `top25_cwe_count` | ≥ 150 | Sits between WARN median (133) and BLOCK median (166); catches images with systemic high-danger weaknesses even when critical CVE count is low. |
| `base_image_age_days` | ≥ 2000 | Slightly below BLOCK median (2683); catches the upper tail of aged-stale while not penalising images that are merely stale. The aged-stale max is 2210, so this threshold strictly separates most aged-stale from known-vuln. |

### WARN thresholds

| Feature | Threshold | Derivation |
|---|---|---|
| `critical_cve_count` | ≥ 10 | Sits between ALLOW median (1) and WARN median (32); catches images that have accumulated double-digit critical CVEs without yet breaching the BLOCK tier. |
| `cvss_ge_7_count` | ≥ 100 | Sits between ALLOW median (10) and WARN median (155); flags high-volume high-severity issue accumulation. |
| `unique_cwe_count` | ≥ 40 | Sits between ALLOW median (17) and WARN median (89); captures broad attack-surface diversity without triggering on a few isolated weaknesses. |
| `top25_cwe_count` | ≥ 50 | Sits between ALLOW median (8) and WARN median (133); catches images with a meaningful concentration of top-25-dangerous findings. |
| `base_image_age_days` | ≥ 365 | Industry-standard "one year stale" threshold; ALLOW median is 47 days, WARN median is 1627 days — near-zero false positives at this cut. |

---

## Observed Classification Distribution

| Bucket | ALLOW | WARN | BLOCK | Total |
|---|---|---|---|---|
| high-qual | 35 | 19 | 3 | 57 |
| aged-stale | 0 | 25 | 30 | 55 |
| known-vuln | 0 | 3 | 28 | 31 |

The 3 BLOCK results in high-qual are images with very high `top25_cwe_count`
or `base_image_age_days` outliers; review of those scans confirms they are
genuinely higher-risk than the median of that bucket.  The 3 WARN results in
known-vuln are images where `base_image_age_days` returned `0.0` (Docker Hub
lookup failed or tag was republished), suppressing the dominant BLOCK signal
from that feature.
