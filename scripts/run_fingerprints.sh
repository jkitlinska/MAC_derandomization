#!/usr/bin/env bash
set -e

SCRIPT_DIR="$( cd -- "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

# (optional) activate venv
# source venv/bin/activate

CONFIGS_DIR="configs/fields"
WORKERS=8
INPUT_TYPE="pcap"

FIELD_CONFIGS=(
    "all_fields_ht_decomposed"
    "best_fields"
    "worst_fields"
)

read_fields_from_yaml() {
    local yaml_file="$1"

    if [[ ! -f "$yaml_file" ]]; then
        echo "Missing YAML config: $yaml_file" >&2
        exit 1
    fi

    awk '
        /^[[:space:]]*active_fields:[[:space:]]*$/ {
            in_active_fields = 1
            next
        }

        in_active_fields && /^[[:space:]]*[A-Za-z0-9_.-]+:[[:space:]]*/ {
            exit
        }

        in_active_fields && /^[[:space:]]*-[[:space:]]*/ {
            line = $0
            sub(/^[[:space:]]*-[[:space:]]*/, "", line)
            gsub(/^"/, "", line)
            gsub(/"$/, "", line)
            gsub(/^'\''/, "", line)
            gsub(/'\''$/, "", line)
            print line
        }
    ' "$yaml_file"
}

run_fingerprints() {
    local label="$1"
    shift

    echo
    echo "=== Running: $label ==="

    if ! python3 -m src.cli.fingerprints "$@"; then
        echo "!!! FAILED: $label" >&2
    fi
}

run_dataset() {
    local dataset_name="$1"
    local label_from="$2"

    for config_name in "${FIELD_CONFIGS[@]}"; do
        local yaml_file="${CONFIGS_DIR}/${config_name}.yaml"

        mapfile -t fields < <(read_fields_from_yaml "$yaml_file")

        if [[ "${#fields[@]}" -eq 0 ]]; then
            echo "No fields found in: $yaml_file" >&2
            exit 1
        fi

        local scenario="${dataset_name}_${config_name}"

        echo
        echo "Dataset: dataset/${dataset_name}"
        echo "Label from: ${label_from}"
        echo "Fields config: ${yaml_file}"
        echo "Scenario: ${scenario}"
        echo "Fields: ${fields[*]}"

        run_fingerprints "${dataset_name} ${config_name}" \
            -d "${dataset_name}" \
            -i "${INPUT_TYPE}" \
            -l \
            --label-from "${label_from}" \
            --workers "${WORKERS}" \
            -f "${fields[@]}" \
            -s "${scenario}"
    done
}

run_dataset "cagliari" "folder"
run_dataset "awid3" "file"