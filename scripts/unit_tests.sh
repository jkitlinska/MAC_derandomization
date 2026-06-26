#!/usr/bin/env bash
set -e

SCRIPT_DIR="$( cd -- "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

# (optional) activate venv
# source venv/bin/activate

run_analysis() {
    local label="$1"
    shift

    echo "=== Running: $label ==="

    if ! python3 -m src.cli.ie_analysis "$@"; then
        echo "!!! FAILED: $label" >&2
    fi
}

ALL_FIELDS=(
    "HT_CAP_INFO"
    "HT_AMPDU_PARMS"
    "HT_MCS_SET"
    "HT_EXT_CAP"
    "HT_Tx"
    "HT_ANTENNA"
    "TAG_LIST"
    "EXT_CAP"
    "DATA_RTS.EXT"
    "DATA_RTS.SUPP"
)

fields_for_unit_test() {
    local unit_test="$1"

    case "$unit_test" in
        UT-MI1|UT-MI2|UT-ST1|UT-ST3|UT-US2|UT-US3)
            printf '%s\n' "${ALL_FIELDS[@]}"
            ;;

        UT-ST2)
            printf '%s\n' \
                "TIME" \
                "RSSI"
            ;;

        UT-US1)
            printf '%s\n' \
                "HT_CAP_INFO" \
                "HT_MCS_SET" \
                "EXT_CAP" \
                "DATA_RTS.SUPP"
            ;;

        *)
            echo "Unknown unit test: $unit_test" >&2
            return 1
            ;;
    esac
}

UNIT_TESTS=(
    "UT-MI1"
    "UT-MI2"
    "UT-ST1"
    "UT-ST2"
    "UT-ST3"
    "UT-US1"
    "UT-US2"
    "UT-US3"
)

for unit_test in "${UNIT_TESTS[@]}"; do
    while IFS= read -r field; do
        dataset_name="${unit_test}_${field}"

        echo
        echo "Running ${unit_test} for ${field}..."
        echo "Dataset: dataset/${dataset_name}"

        run_analysis "${unit_test} ${field}" \
            -d "${dataset_name}" \
            -i pcap \
            -l \
            --label-from folder \
            --workers 8 \
            --field "${field}" \
            --full-analysis

    done < <(fields_for_unit_test "$unit_test")
done