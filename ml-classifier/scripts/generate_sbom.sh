
#!/bin/bash

run_trivy_scan() {
    local IMAGE="$1"
    local OUTPUT_FILE="$2"

    # Handle parameterization
    if [[ "$IMAGE" == "" ]] || [[ "$OUTPUT_FILE" == "" ]]; then
        echo "Usage: $0 <image> <output_file>"
        echo ""
        echo "Description:"
        echo "  Scans a specified container image for vulnerabilities and"
        echo "  misconfigurations using Trivy, outputting to CycloneDX format."
        echo ""
        echo "Arguments:"
        echo "  <image>        The container image to scan (e.g., ubuntu:latest)"
        echo "  <output_file>  The file path to save the generated report"
        return 1
    fi

    # Ensure trivy is a viable service
    if ! command -v trivy >/dev/null 2>&1; then
        echo "Error: 'trivy' command not found. Please ensure it is installed and in your PATH." >&2
        return 1
    fi

    # Ensure that parent directories are created
    if [[ "$OUTPUT_FILE" == *"/"* ]]; then
        mkdir -p "$(dirname "$OUTPUT_FILE")"
    fi

    # Scan the image
    if ! sudo trivy image --image-config-scanners misconfig --format cyclonedx --scanners vuln --output "$OUTPUT_FILE" "$IMAGE"; then
        echo "Error: Trivy scan failed during execution." >&2
        return 1
    fi
}

run_trivy_scan_from_csv() {
    local CSV_FILE="$1"
    local OUTPUT_DIRECTORY="$2"

    if [[ "$CSV_FILE" == "" ]]; then
        echo "Usage: run_trivy_scan_from_csv <csv_file> <output_directory>"
        return 1
    fi

    if [[ ! -f "$CSV_FILE" ]]; then
        echo "Error: File '$CSV_FILE' not found." >&2
        return 1
    fi

    # Count non-empty lines so we can report [N/total] progress
    local total
    total=$(grep -c '[^[:space:]]' "$CSV_FILE" || true)

    local index=0
    local failed=0
    while IFS=',' read -r image output_file || [[ -n "$image" ]]; do
        if [[ -n "$image" ]] && [[ -n "$output_file" ]]; then
            index=$(( index + 1 ))
            echo "[$index/$total] Scanning $image ..."
            if run_trivy_scan "$image" "$OUTPUT_DIRECTORY/$output_file"; then
                echo "[$index/$total] OK: $image"
            else
                echo "[$index/$total] FAILED: $image" >&2
                failed=1
            fi
        fi
    done < "$CSV_FILE"

    return $failed
}

if [[ "$1" == "GENERATE_SBOM" ]]; then
    time run_trivy_scan "$2" "$3"
elif [[ "$1" == "GENERATE_SBOM_FROM_LIST" ]]; then
    time run_trivy_scan_from_csv "$2" "$3"
else
    echo "Error: Invalid or missing directive." >&2
    echo "Usage: $0 <GENERATE_SBOM|GENERATE_SBOM_FROM_LIST> [arguments...]" >&2
    exit 1
fi
