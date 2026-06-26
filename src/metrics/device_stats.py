# metrics/device_stats.py
from collections import defaultdict
from typing import Any, Counter, Dict, Hashable, List, Sequence, Tuple

from src.metrics.distributions import distribution_from_counts
from src.metrics.cardinality import per_group_cardinality
from src.metrics.common import count_frames_in_req, get_field_value_from_req, normalize_value, extract_labels
from src.metrics.info_theory import conditional_entropy, entropy_from_counts, mutual_information, normalized_mutual_information
from src.metrics.stability import find_representative_value

def calculate_per_device_distribution(
    MACs: List[Dict[str, Any]],
    field_name: str,
    normalize: bool = False,
):
    print(f"Calculating PER-DEVICE distribution for field '{field_name}'...")

    values = defaultdict(set)
    counts = {}

    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        for pr in mac.get("PROBE_REQs", []):
            data = pr.get("DATA", {})
            
            raw_value = get_field_value_from_req(pr, field_name)
            value = normalize_value(raw_value)

            values[value].add(label)

    for key, labels in values.items():
        counts[key] = len(set(labels))

    return distribution_from_counts(counts, normalize=normalize)

def device_field_distribution(
        MACs: List[Dict[str, Any]],
        field_name: str
): 
    distribution = defaultdict(dict)

    devices = extract_labels(MACs)
    for device in devices:
        values_occurences, representative_value = find_representative_value(MACs, field_name, device)
        distribution[device] = values_occurences
    
    return distribution

def calculate_device_k_perspective(
    MACs: List[Dict[str, Any]],
    field_name: str,
    distribution: Dict[str, Any],
):

    label_to_values = defaultdict(set)
    label_to_k = defaultdict(set)

    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        for pr in mac.get("PROBE_REQs", []):
            data = pr.get("DATA", {})

            raw_value = get_field_value_from_req(pr, field_name)
            value = normalize_value(raw_value)
            
            label_to_values[label].add(value)
    
    for label, values in label_to_values.items():
        for value in values:
            label_to_k[label].add(distribution[value])

    return {dev: min(ks) for dev, ks in label_to_k.items()}


def calculate_per_device_cardinality(
    MACs: List[Dict[str, Any]],
    field_name: str,
) -> int:
    values = {}

    for mac in MACs:
        key = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        for pr in mac.get("PROBE_REQs", []):
            value = normalize_value(get_field_value_from_req(pr, field_name))
            if key not in values:
                values[key] = set()
            values[key].add(value)

    return per_group_cardinality(values)

def calculate_global_conditional_entropy_H_XY(
    MACs: List[Dict[str, Any]],
    field_name: str,
):
    """
        H(X|Y) - how much do we know about field value if we know the device
    """

    label_to_counts: Dict[Hashable, Dict[Hashable, int]] = defaultdict(Counter)

    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        for pr in mac.get("PROBE_REQs", []):
            data = pr.get("DATA", {})

            raw_value = get_field_value_from_req(pr, field_name)
            value = normalize_value(raw_value)

            # number of frames with this field value
            n_time = count_frames_in_req(pr)
            if n_time == 0:
                continue

            label_to_counts[label][value] += n_time

    # liczenie entropii na podstawie tego słownika
    return conditional_entropy(label_to_counts)

def calculate_global_conditional_entropy_H_YX(
    MACs: List[Dict[str, Any]],
    field_name: str,
):
    """
        H(Y|X) - how much do we know about device if we know the field value
    """

    value_to_counts: Dict[Hashable, Dict[Hashable, int]] = defaultdict(Counter)

    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        for pr in mac.get("PROBE_REQs", []):
            data = pr.get("DATA", {})

            raw_value = get_field_value_from_req(pr, field_name)
            value = normalize_value(raw_value)

            # number of frames with this field value
            n_time = count_frames_in_req(pr)
            if n_time == 0:
                continue

            value_to_counts[value][label] += n_time

    # liczenie entropii na podstawie tego słownika
    return conditional_entropy(value_to_counts)

def calculate_mutual_information(
    MACs: List[Dict[str, Any]],
    field_name: str,
):
    label_to_counts: Dict[Hashable, Dict[Hashable, int]] = defaultdict(Counter)

    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        for pr in mac.get("PROBE_REQs", []):
            data = pr.get("DATA", {})
            
            raw_value = get_field_value_from_req(pr, field_name)
            value = normalize_value(raw_value)

            # number of frames with this field value
            n_time = count_frames_in_req(pr)
            if n_time == 0:
                continue

            label_to_counts[label][value] += n_time

    return mutual_information(label_to_counts)

def calculate_normalized_mutual_information(
    MACs: List[Dict[str, Any]],
    field_name: str,
    H_x: float,
    H_y: float
):
    label_to_counts: Dict[Hashable, Dict[Hashable, int]] = defaultdict(Counter)

    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        for pr in mac.get("PROBE_REQs", []):
            data = pr.get("DATA", {})
            
            raw_value = get_field_value_from_req(pr, field_name)
            value = normalize_value(raw_value)

            # number of frames with this field value
            n_time = count_frames_in_req(pr)
            if n_time == 0:
                continue

            label_to_counts[label][value] += n_time

    return normalized_mutual_information(label_to_counts, H_x, H_y)

def calculate_device_entropy(
        MACs: List[Dict[str, Any]], 
):
    """
    devices: a list of dictionaries, similar to the PCAP/JSON loader
             [{ “MAC”: “...”, “PROBE_REQs”: [...], ... }, ...]
    field_name: e.g., “HT_CAP”, ‘EXT_CAP’, “VHT_CAP”

    number of frames with the same MAC
    """
    print(f"Calculating entropy for devices...")

    counts = Counter()

    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        for pr in mac.get("PROBE_REQs", []):

            # number of frames with this field value
            n_time = count_frames_in_req(pr)
            if n_time == 0:
                continue

            counts[label] += n_time

    # dictionary {field_value: count (sum of TIME lengths)}
    counts_dict = dict(counts)

    # liczenie entropii na podstawie tego słownika
    return entropy_from_counts(counts_dict)

def count_affected_devices(
    MACs: List[Dict[str, Any]],
    field_name: str,
) -> int:
    labels = set()

    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        for pr in mac.get("PROBE_REQs", []):
            raw_value = get_field_value_from_req(pr, field_name)
            value = normalize_value(raw_value)

            if value != "NULL":
                labels.add(label)

    return len(labels)

def calculate_affected_device_percentage(
    MACs: List[Dict[str, Any]],
    field_name: str,
) -> float:
    total_devices = 0
    labels = set()
    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        labels.add(label)

    total_devices = len(labels)
    affected_devices = count_affected_devices(MACs, field_name)

    if total_devices == 0:
        return 0.0

    return (affected_devices / total_devices) * 100.0
