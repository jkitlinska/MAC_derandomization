from collections import defaultdict
from typing import Any, List, Dict

from src.metrics.common import count_frames_in_req, get_field_value_from_req, normalize_value, extract_labels


def find_representative_value(MACs: List[Dict[str, Any]], field_name: str, device_label: str) -> Dict[str, int]:
    counts = {}

    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        if label == device_label:
            for pr in mac.get("PROBE_REQs", []):
                raw_value = get_field_value_from_req(pr, field_name)
                value = normalize_value(raw_value)

                n_time = count_frames_in_req(pr)
                if n_time == 0:
                    continue
                
                counts[value] = counts.get(value, 0) + n_time

    representative_value = max(counts, key=counts.get) if counts else None

    return counts, representative_value

def calculate_distance(values_occurences, representative_value):
    distance = 0
    for value, occurence in values_occurences.items():
        # print(f"Value: {value}, Occurence: {occurence}, Representative: {representative_value}")
        if value != representative_value:
            distance = distance + 1*occurence

    distance = distance / sum(values_occurences.values()) if sum(values_occurences.values()) > 0 else 0
    # print(f"Calculated distance: {distance}")

    return distance

def calculate_stability(
    MACs: List[Dict[str, Any]],
    field_name: str,
):
    devices_stabilities = {}
    stability = 0

    devices = extract_labels(MACs)

    for device in devices:
        values_occurences, representative_value = find_representative_value(MACs, field_name, device)
        device_distance = calculate_distance(values_occurences, representative_value)
        devices_stabilities[device] = 1-device_distance

    stability = sum(devices_stabilities.values()) / len(devices_stabilities) if devices_stabilities else 0

    return stability, devices_stabilities