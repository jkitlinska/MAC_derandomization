#!/usr/bin/env bash
set -euo pipefail

BASE_DATASET_DIR="./dataset"

# argument: subdirectory name (np. Training, Others)
SUBDIR="${1:-}"
if [[ -z "$SUBDIR" ]]; then
  echo "Usage: $0 <subfolder_inside_dataset>"
  echo "Example: $0 Others"
  exit 1
fi

DATASET_DIR="${BASE_DATASET_DIR}/${SUBDIR%/}"

if [[ ! -d "$DATASET_DIR" ]]; then
  echo "Error: directory not found: $DATASET_DIR"
  exit 1
fi

NOT_PROBE_FILTER='!wlan.fcs.bad_checksum && wlan.fc.type_subtype != 0x0004 && !(_ws.expert.group == 0x07000000)'

total_not_probe=0

for DIR in "$DATASET_DIR"/*/; do
  [[ -d "$DIR" ]] || continue
  echo "Processing directory $DIR ..."

  shopt -s nullglob
  for FILE in "$DIR"/*; do
    [[ -f "$FILE" ]] || continue

    # pcap/pcapng files only, skip others
    case "${FILE,,}" in
      *.pcap|*.pcapng) ;;
      *) continue ;;
    esac

    echo "  Processing file $FILE ..."

    # Count non–Probe Request frames in the current file
    count_not_probe=$(
      tshark -r "$FILE" -Y "$NOT_PROBE_FILTER" -T fields -e frame.number 2>/dev/null | wc -l
    )

    total_not_probe=$(( total_not_probe + count_not_probe ))
  done
  shopt -u nullglob
done

echo "----------------------------------------"
echo "Total non–Probe Request frames in '$DATASET_DIR': $total_not_probe"
