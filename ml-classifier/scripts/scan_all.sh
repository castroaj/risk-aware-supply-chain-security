#!/bin/bash
#
# scan_all.sh — Scan all three training-set image lists and store results
# under <output-dir>/{high-qual,aged-stale,known-vuln}/.
#
# Usage:
#   ./scripts/scan_all.sh [-p] [-s] <output-dir>
#
# Options:
#   -p, --parallel       Run all three bucket scans concurrently (background jobs).
#                        Each bucket's output is captured in <output-dir>/<bucket>/scan.log.
#   -s, --skip-existing  Skip any image whose output JSON already exists in the
#                        bucket output directory. Useful for scanning only newly
#                        added images without re-pulling already-scanned ones.
#   <output-dir>         Required. Root directory for scan results. The three
#                        bucket sub-directories are created automatically.
#
# Prerequisites:
#   Trivy pulls images from Docker Hub. You must be logged in before running:
#     docker login
#
# Rate-limit warning:
#   A personal authenticated Docker Hub account allows 200 pulls per 6-hour
#   window. Use -p / --parallel with caution — all three buckets pull
#   concurrently, which can exhaust the quota faster than sequential mode.
#   Exceeding the limit will cause Trivy pulls to fail mid-scan.

set -uo pipefail

# ---------------------------------------------------------------------------
# Graceful shutdown — kill all tracked background processes on INT/TERM.
# SCAN_PIDS and WATCHER_PIDS are populated as jobs are launched so the trap
# always has a complete list, regardless of how far the script got.
# ---------------------------------------------------------------------------
SCAN_PIDS=()
WATCHER_PIDS=()

cleanup() {
    echo "" >&2
    echo "Interrupted — stopping all background processes..." >&2
    for pid in "${SCAN_PIDS[@]+"${SCAN_PIDS[@]}"}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${WATCHER_PIDS[@]+"${WATCHER_PIDS[@]}"}"; do
        kill "$pid" 2>/dev/null || true
    done
    exit 130
}

trap cleanup INT TERM

# ---------------------------------------------------------------------------
# usage — print help to stderr and exit 1
# ---------------------------------------------------------------------------
usage() {
    echo "Usage: $0 [-p] [-s] <output-dir>" >&2
    echo "" >&2
    echo "  -p, --parallel       Run all three bucket scans concurrently." >&2
    echo "  -s, --skip-existing  Skip images whose output JSON already exists." >&2
    echo "  <output-dir>         Directory to write results into. Sub-directories" >&2
    echo "                       high-qual/, aged-stale/, and known-vuln/ are created inside." >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
PARALLEL=0
SKIP_EXISTING=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--parallel)      PARALLEL=1;       shift ;;
        -s|--skip-existing) SKIP_EXISTING=1;  shift ;;
        -*) echo "Error: unrecognized flag: $1" >&2; echo "" >&2; usage ;;
        *)  break ;;
    esac
done

[[ $# -lt 1 || -z "$1" ]] && usage

OUTPUT_BASE="$1"

# ---------------------------------------------------------------------------
# Resolve paths relative to this script's location
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ML_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

GENERATE_SBOM="$SCRIPT_DIR/generate_sbom.sh"
IMAGE_LISTS_DIR="$ML_DIR/data/image-lists"

BUCKETS=("high-qual" "aged-stale" "known-vuln")

# ---------------------------------------------------------------------------
# Validate that every bucket's image-list CSV exists before doing any work
# ---------------------------------------------------------------------------
for bucket in "${BUCKETS[@]}"; do
    csv="$IMAGE_LISTS_DIR/$bucket.csv"
    if [[ ! -f "$csv" ]]; then
        echo "Error: image list not found: $csv" >&2
        exit 1
    fi
done

echo "Output: $OUTPUT_BASE"
echo ""

# ---------------------------------------------------------------------------
# Sequential scan (default)
# ---------------------------------------------------------------------------
run_sequential() {
    local skip_flag=()
    [[ "$SKIP_EXISTING" -eq 1 ]] && skip_flag=("--skip-existing")

    for bucket in "${BUCKETS[@]}"; do
        csv="$IMAGE_LISTS_DIR/$bucket.csv"
        out_dir="$OUTPUT_BASE/$bucket"

        echo "=== $bucket ==="
        mkdir -p "$out_dir"
        bash "$GENERATE_SBOM" GENERATE_SBOM_FROM_LIST "${skip_flag[@]+"${skip_flag[@]}"}" "$csv" "$out_dir"
        echo ""
    done
}

# ---------------------------------------------------------------------------
# Parallel scan — each bucket runs as a background job; stdout+stderr are
# captured in <bucket>/scan.log. A paired tail+awk process streams each
# log to the terminal with a [bucket] prefix so progress is visible without
# output from different buckets interleaving. Exit codes are collected after
# all scan jobs finish; any failure exits non-zero.
# ---------------------------------------------------------------------------
run_parallel() {
    declare -A PIDS
    declare -A TAIL_PIDS

    for bucket in "${BUCKETS[@]}"; do
        csv="$IMAGE_LISTS_DIR/$bucket.csv"
        out_dir="$OUTPUT_BASE/$bucket"
        mkdir -p "$out_dir"

        # Touch log so tail -f can open it immediately, before the scan writes anything
        touch "$out_dir/scan.log"

        # Stream log lines to terminal with a [bucket] prefix; awk fflush() ensures
        # lines appear as they are written rather than being held in a buffer
        tail -f "$out_dir/scan.log" \
            | awk -v b="[$bucket]" '{ print b, $0; fflush() }' &
        TAIL_PIDS[$bucket]=$!
        WATCHER_PIDS+=("$!")   # register with trap

        echo "Starting: $bucket"
        local skip_flag=()
        [[ "$SKIP_EXISTING" -eq 1 ]] && skip_flag=("--skip-existing")
        bash "$GENERATE_SBOM" GENERATE_SBOM_FROM_LIST "${skip_flag[@]+"${skip_flag[@]}"}" "$csv" "$out_dir" \
            >"$out_dir/scan.log" 2>&1 &
        PIDS[$bucket]=$!
        SCAN_PIDS+=("$!")      # register with trap
    done

    echo ""

    # Wait for every scan job, then stop its tail watcher and report pass/fail
    local failed=0
    for bucket in "${!PIDS[@]}"; do
        if ! wait "${PIDS[$bucket]}"; then
            echo "FAILED: $bucket (see $OUTPUT_BASE/$bucket/scan.log)" >&2
            failed=1
        else
            echo "OK:     $bucket"
        fi
        kill "${TAIL_PIDS[$bucket]}" 2>/dev/null || true
    done

    return $failed
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if [[ $PARALLEL -eq 1 ]]; then
    run_parallel
else
    run_sequential
fi

echo "Done. Results in: $OUTPUT_BASE"
