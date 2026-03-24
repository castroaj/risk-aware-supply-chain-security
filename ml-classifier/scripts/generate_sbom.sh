#!/bin/bash
#
# generate_sbom.sh — Scan a container image (or a list of images) with Trivy
# and write the result as a CycloneDX JSON SBOM.
#
# Usage:
#   ./scripts/generate_sbom.sh GENERATE_SBOM <image:tag> <output.json>
#   ./scripts/generate_sbom.sh GENERATE_SBOM_FROM_LIST <image-list.csv> <output-dir/>
#
# Directives:
#   GENERATE_SBOM            Scan a single image and write one JSON file.
#   GENERATE_SBOM_FROM_LIST  Read a CSV of image:tag,filename pairs and scan
#                            each one into <output-dir>/<filename>.
#
# Prerequisites:
#   - trivy must be installed and on PATH
#   - sudo privileges are required (trivy image runs under sudo)
#   - Docker Hub login is required to avoid unauthenticated pull rate limits:
#       docker login

set -uo pipefail

# ---------------------------------------------------------------------------
# run_trivy_scan — scan a single image and write a CycloneDX JSON SBOM.
#
# Arguments:
#   $1  image:tag   — the container image to scan
#   $2  output.json — destination file path (parent directories are created)
# ---------------------------------------------------------------------------
run_trivy_scan() {
    local image="$1"
    local output_file="$2"

    if [[ -z "$image" || -z "$output_file" ]]; then
        echo "Usage: $0 GENERATE_SBOM <image:tag> <output.json>" >&2
        return 1
    fi

    if ! command -v trivy >/dev/null 2>&1; then
        echo "Error: 'trivy' not found. Install it and ensure it is on PATH." >&2
        return 1
    fi

    # Create parent directories if the output path contains a subdirectory
    if [[ "$output_file" == *"/"* ]]; then
        mkdir -p "$(dirname "$output_file")"
    fi

    if ! sudo trivy image \
            --image-config-scanners misconfig \
            --format cyclonedx \
            --scanners vuln \
            --output "$output_file" \
            "$image"; then
        echo "Error: Trivy scan failed for $image" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# run_trivy_scan_from_csv — scan every image listed in a CSV file.
#
# CSV format (no header): image:tag,output-filename.json
# Each SBOM is written to <output_dir>/<output-filename.json>.
# Progress is reported as [N/total] lines. Failures are noted but scanning
# continues; the function returns 1 if any image failed.
#
# Arguments:
#   $1  csv_file        — path to the image-list CSV
#   $2  output_dir      — directory to write SBOM JSON files into
# ---------------------------------------------------------------------------
run_trivy_scan_from_csv() {
    local csv_file="$1"
    local output_dir="$2"

    if [[ -z "$csv_file" ]]; then
        echo "Usage: $0 GENERATE_SBOM_FROM_LIST <image-list.csv> <output-dir/>" >&2
        return 1
    fi

    if [[ ! -f "$csv_file" ]]; then
        echo "Error: CSV file not found: $csv_file" >&2
        return 1
    fi

    # Count non-empty lines upfront for [N/total] progress reporting
    local total
    total=$(grep -c '[^[:space:]]' "$csv_file" || true)

    local index=0
    local failed=0
    while IFS=',' read -r image output_file || [[ -n "$image" ]]; do
        # Skip blank lines or lines missing either field
        [[ -z "$image" || -z "$output_file" ]] && continue

        index=$(( index + 1 ))
        echo "[$index/$total] Scanning $image ..."
        if run_trivy_scan "$image" "$output_dir/$output_file"; then
            echo "[$index/$total] OK: $image"
        else
            echo "[$index/$total] FAILED: $image" >&2
            failed=1
        fi
    done < "$csv_file"

    return $failed
}

# ---------------------------------------------------------------------------
# Entry point — dispatch on the directive passed as $1
# ---------------------------------------------------------------------------
case "${1:-}" in
    GENERATE_SBOM)
        time run_trivy_scan "$2" "$3"
        ;;
    GENERATE_SBOM_FROM_LIST)
        time run_trivy_scan_from_csv "$2" "$3"
        ;;
    *)
        echo "Error: invalid or missing directive: '${1:-}'" >&2
        echo "Usage: $0 <GENERATE_SBOM|GENERATE_SBOM_FROM_LIST> [arguments...]" >&2
        exit 1
        ;;
esac
