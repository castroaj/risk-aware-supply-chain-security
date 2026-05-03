# Feature Proposal: `is_eol` — OS End-of-Life Detection via Trivy Native JSON

## Problem

The current 8-feature vector cannot distinguish between two structurally identical scan results:

| Image | `total_dependency_count` | `vuln_total` | All other features |
|---|---|---|---|
| `alpine:3.21` (current, actively patched) | ~100 | 0 | 0 |
| `alpine:3.13` (EOL Nov 2022, sparse Trivy DB) | ~40 | 0 | 0 |

Both produce an identical feature vector. The LLM labeler (and threshold rules) have no basis to label them differently — yet `alpine:3.13` represents a meaningfully higher supply chain risk because it will never receive CVE patches and Trivy's vulnerability database has sparse coverage for it.

This creates a labeling ambiguity: a zero-vulnerability scan on an EOL image is a **false-clean** (Trivy simply has no advisories to report), not a genuine security signal.

## Root Cause

The current scan command uses `--format cyclonedx`:

```bash
sudo trivy image \
    --image-config-scanners misconfig \
    --format cyclonedx \
    --scanners vuln \
    --output "$output_file" \
    "$image"
```

CycloneDX 1.6 has no standard field for OS lifecycle status, and Trivy does not inject EOSL information as a custom `aquasecurity:trivy:*` property in the SBOM output. The OS component in the CycloneDX JSON only carries `name` and `version` — no lifecycle metadata.

## What Trivy Already Knows

Trivy internally tracks OS end-of-life status using its own built-in EOL database (the `--ignore-status end_of_life` flag proves this). This information is exposed in **Trivy's native JSON format** (`--format json`) as an `EOSL` boolean field on each scan target:

**EOL image — empty vulnerability list but EOSL=true:**
```json
{
  "Results": [
    {
      "Target": "alpine:3.13",
      "Type": "alpine",
      "Class": "os-pkgs",
      "EOSL": true,
      "Vulnerabilities": null
    }
  ]
}
```

**Current image — empty vulnerability list and EOSL=false:**
```json
{
  "Results": [
    {
      "Target": "alpine:3.21",
      "Type": "alpine",
      "Class": "os-pkgs",
      "EOSL": false,
      "Vulnerabilities": null
    }
  ]
}
```

This distinction is derived entirely from Trivy's scan — no external API calls, no hardcoded date tables, no network dependencies beyond what scanning already requires. It satisfies the project constraint that **ground truth must come from the SBOM scan toolchain**.

## Proposed Solution

### Option A — Companion JSON scan (recommended)

Add a second Trivy invocation per image in `generate_sbom.sh` that writes a native JSON companion file alongside the existing CycloneDX output:

```bash
# Existing CycloneDX scan (unchanged)
sudo trivy image \
    --image-config-scanners misconfig \
    --format cyclonedx \
    --scanners vuln \
    --output "$output_file" \
    "$image"

# New companion JSON scan for EOSL extraction
companion_file="${output_file%.json}-trivy.json"
sudo trivy image \
    --format json \
    --scanners vuln \
    --output "$companion_file" \
    "$image"
```

`sbom_extractor.py` would look for the companion file at scan time and extract `is_eol`:

```python
def extract_is_eol(companion_json: dict) -> float:
    """Returns 1.0 if the OS is flagged EOSL by Trivy, 0.0 otherwise."""
    for result in companion_json.get("Results", []):
        if result.get("Class") == "os-pkgs" and result.get("EOSL", False):
            return 1.0
    return 0.0
```

The `SecurityMetric` dataclass gains a 9th feature:

```python
@dataclass
class SecurityMetric:
    scan_file: str
    total_dependency_count: float
    vuln_total: float
    critical_cve_count: float
    high_cve_count: float
    cvss_ge_7_count: float
    max_cvss: float
    unique_cwe_count: float
    top25_cwe_count: float
    is_eol: float              # NEW: 1.0 if Trivy reports EOSL, else 0.0
```

### Option B — Switch primary format to Trivy JSON

Drop CycloneDX entirely and parse all features from native Trivy JSON. Feature extraction becomes more direct (e.g., `Vulnerabilities[].Severity` instead of navigating CycloneDX ratings arrays). Downside: loses SBOM standard compliance, which is a stated goal of the CI/CD pipeline prototype (`software-prototype/`).

### Option C — CycloneDX `end_of_life` vulnerability status (partial)

Trivy marks individual vulnerability entries with `status: end_of_life` even in CycloneDX format — but only when vulnerabilities ARE found. For the sparse-DB false-clean case (zero vulnerabilities on an EOL image), there are no vulnerability objects to attach the status to. This only partially solves the problem and misses the exact scenario that motivated this proposal.

**Option A is the only approach that fully resolves the ambiguity while preserving the CycloneDX SBOM format.**

## Impact on System Prompt

With `is_eol` as a feature, the v4 system prompt would add guidance such as:

> If `is_eol = 1` and all vulnerability features are zero, label **WARN** — this reflects sparse Trivy DB coverage for an EOL distribution, not genuine security hygiene. The absence of reported vulnerabilities does not indicate safety for unsupported OS versions.
>
> If `is_eol = 0` and all vulnerability features are zero, label **ALLOW** — this is a genuinely clean scan of an actively maintained image.

## Scope of Changes

| File | Change |
|---|---|
| `scripts/generate_sbom.sh` | Add second `--format json` Trivy invocation per image |
| `src/classifier/sbom_extractor.py` | Add `is_eol` to `SecurityMetric`, add `extract_is_eol()`, update parsing to look for companion JSON |
| `config/system-prompt-v4.md` | Add `is_eol` feature definition and EOSL-specific labeling guidance |
| `data/scans/*/` | Companion `*-trivy.json` files alongside existing CycloneDX JSONs |
| All existing label CSVs | Must be regenerated — `is_eol` changes the feature vector, invalidating prior labels |
| `analysis/dataset-statistics.md` | Update with 9-feature statistics |

## Prerequisites

- All existing 371 images would need re-scanning to generate the companion JSON files
- Approximately doubles the disk footprint of `data/scans/` (one extra JSON per image)
- Trivy version 0.69.1+ confirmed to support `EOSL` field in native JSON output

## When to Implement

Consider implementing this feature when:
- The ALLOW class remains severely underrepresented after dataset expansion
- The model shows consistent confusion between EOL-clean and genuinely-clean images
- A model version bump (e.g., 0.0.8 → 0.0.9) provides a clean re-scan opportunity

This is not a blocker for the current dataset expansion (adding ~155 new images to reach ~1.5x). The EOL-clean images added during expansion will still contribute valid WARN training signal even if labeled conservatively by the LLM based on v3 system prompt guidance.
