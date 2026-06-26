#!/usr/bin/env bash

BASE_DATASET_DIR="./dataset/cagliari/pcaps"

run_analysis() {
    local label="$1"
    local rel_path="$2"

    echo "========================================"
    echo "$label"
    echo "Path: $rel_path"
    echo "========================================"

    if ! python3 scripts/utilities/count_frames.py --path "$rel_path" --probe-only; then
        echo "!!! FAILED: $label" >&2
    fi

    echo
}

if [[ ! -d "$BASE_DATASET_DIR" ]]; then
    echo "Catalog does not exist: $BASE_DATASET_DIR" >&2
    exit 1
fi

found_any=false

for subdir in "$BASE_DATASET_DIR"/*/; do
    [[ -d "$subdir" ]] || continue
    found_any=true

    device_name=$(basename "$subdir")
    rel_path="cagliari/pcaps/$device_name" # change according to the relative path from the script's location

    run_analysis "Cagliari frames for device $device_name" "$rel_path"
done

if [[ "$found_any" = false ]]; then
    echo "No subdirectories found in $BASE_DATASET_DIR" >&2
    exit 1
fi