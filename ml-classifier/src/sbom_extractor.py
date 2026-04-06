"""
Backward-compatibility shim.

sbom_extractor has moved into the classifier package:
    src/classifier/sbom_extractor.py

All public names are re-exported here so that existing callers using
`import sbom_extractor` continue to work without modification.

To invoke the extractor CLI directly, prefer:
    python src/classifier/sbom_extractor.py -s <path>
"""
from classifier.sbom_extractor import (  # noqa: F401
    JSON_OUTPUT,
    CSV_OUTPUT,
    TOP_25_CWES,
    SEVERITY_WEIGHT,
    BLOCK_THRESHOLDS,
    WARN_THRESHOLDS,
    FEATURES,
    SecurityMetric,
    SecurityMetricsCollection,
    extract_total_dependency_count,
    extract_vuln_total,
    extract_critical_cve_count,
    extract_high_cve_count,
    extract_cvss_ge_7_count,
    extract_max_cvss,
    extract_unique_cwe_count,
    extract_top25_cwe_count,
    extract_base_image_days,
    classify_metric,
    build_security_metric_from_sbom,
    read_path_data,
    validate_file_path,
    validate_output_path,
    parse_args,
)

if __name__ == "__main__":
    import runpy
    from pathlib import Path
    runpy.run_path(
        str(Path(__file__).parent / "classifier" / "sbom_extractor.py"),
        run_name="__main__",
    )
