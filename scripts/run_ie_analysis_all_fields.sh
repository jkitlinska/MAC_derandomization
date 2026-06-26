#!/usr/bin/env bash
set -e

SCRIPT_DIR="$( cd -- "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

# (optional) activate venv
# source venv/bin/activate

run_analysis() {
    local label="$1"
    shift

    echo
    echo "=== Running: $label ==="

    if ! python3 -m src.cli.ie_analysis "$@"; then
        echo "!!! FAILED: $label" >&2
    fi
}

DATASET_NAME="cagliari_HT"
INPUT_TYPE="pcap"
WORKERS=12

FIELDS=(
    "HT_CAP"
    "HT_CAP_INFO"
    "HT_AMPDU_PARMS"
    "HT_MCS_SET"
    "HT_EXT_CAP"
    "HT_Tx"
    "HT_ANTENNA"
    "TAG_LIST"
    "EXT_CAP"
    "DATA_RTS.SUPP"
    "DATA_RTS.EXT"
)

for field in "${FIELDS[@]}"; do
    echo
    echo "Running IE analysis for field: ${field}"
    echo "Dataset: dataset/${DATASET_NAME}"

    run_analysis "IE analysis ${field}" \
        -d "${DATASET_NAME}" \
        -i "${INPUT_TYPE}" \
        -l \
        --label-from folder \
        --workers "${WORKERS}" \
        --field "${field}" \
        --full-analysis
done