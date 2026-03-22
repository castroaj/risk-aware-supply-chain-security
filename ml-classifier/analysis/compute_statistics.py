import pandas as pd
import io
import subprocess
import sys
from pathlib import Path

# Resolve paths relative to this script's location
HERE = Path(__file__).parent

buckets: dict[str, Path] = {
    "high-qual":  HERE.parent / "data" / "scans" / "high-qual",
    "aged-stale": HERE.parent / "data" / "scans" / "aged-stale",
    "known-vuln": HERE.parent / "data" / "scans" / "known-vuln",
}

SBOM_EXTRACTOR = HERE.parent / "src" / "sbom_extractor.py"

features = [
    "total_dependency_count", "vuln_total", "critical_cve_count", "high_cve_count",
    "cvss_ge_7_count", "max_cvss", "unique_cwe_count", "top25_cwe_count",
    "base_image_age_days"
]

for label, path in buckets.items():
    result = subprocess.run(
        [sys.executable, str(SBOM_EXTRACTOR), "-s", str(path), "-f", "csv"],
        capture_output=True, text=True
    )
    df = pd.read_csv(io.StringIO(result.stdout))
    print(f"\n=== {label} (n={len(df)}) ===")
    print(df[features].agg(["min", "median", "mean", "max"]).round(1).to_string())
