# metrics/field_stats.py
from collections import Counter
from typing import Dict, Any, List

from .info_theory import entropy_from_counts
from .common import count_frames_in_req, get_field_value_from_req, normalize_value
from .distributions import distribution_from_counts
from src.metrics.cardinality import cardinality_from_values
from src.metrics.stability import calculate_stability


def calculate_field_entropy(devices: List[Dict[str, Any]], field_name: str):
    """
    devices: a list of dictionaries, similar to the PCAP/JSON loader
             [{ “MAC”: “...”, “PROBE_REQs”: [...], ... }, ...]
    field_name: e.g., “HT_CAP”, ‘EXT_CAP’, “VHT_CAP”
    """
    print(f"Calculating entropy for {field_name}...")

    counts = Counter()

    for dev in devices:
        for pr in dev.get("PROBE_REQs", []):
            data = pr.get("DATA", {})

            raw_value = get_field_value_from_req(pr, field_name)
            value = normalize_value(raw_value)

            # number of frames with this field value
            n_time = count_frames_in_req(pr)
            if n_time == 0:
                continue

            counts[value] += n_time

    # dictionary {field_value: count (sum of TIME lengths)}
    counts_dict = dict(counts)

    # liczenie entropii na podstawie tego słownika
    return entropy_from_counts(counts_dict)

def calculate_field_distribution(
    MACs: List[Dict[str, Any]],
    field_name: str,
    normalize: bool = False,
):
    """
    Global distribution of a field's values across the entire dataset.
    Counts the total number of frames (len(TIME)) for each field value.

    :return: {wartość_pola: liczność lub P(wartość_pola)}
    """
    print(f"Calculating GLOBAL distribution for field '{field_name}'...")

    counts = Counter()

    for mac in MACs:
        for pr in mac.get("PROBE_REQs", []):
            data = pr.get("DATA", {})

            raw_value = get_field_value_from_req(pr, field_name)
            value = normalize_value(raw_value)

            n_time = count_frames_in_req(pr)
            if n_time == 0:
                continue

            counts[value] += n_time

    counts_dict = dict(counts)
    print(f"Counts for field '{field_name}': {counts_dict}")
    return distribution_from_counts(counts_dict, normalize=normalize)

def calculate_field_cardinality(
    MACs: List[Dict[str, Any]],
    field_name: str,
) -> int:
    values = [
        normalize_value(get_field_value_from_req(pr, field_name))
        for mac in MACs
        for pr in mac.get("PROBE_REQs", [])
    ]

    count, _ = cardinality_from_values(values)
    return count

def count_fields_occurrences(
    MACs: List[Dict[str, Any]]
):
    counts = {}

    for mac in MACs:
        for pr in mac.get("PROBE_REQs", []):
            data = pr.get("DATA", {})
            for field_name, raw_value in data.items():
                n_time = count_frames_in_req(pr)
                if n_time == 0:
                    continue

                if field_name not in counts:
                    counts[field_name] = 0
                
                counts[field_name] += n_time
    return counts

def field_stability(
    MACs:List[Dict[str, Any]],
    field_name:str
):
    
    return calculate_stability(MACs, field_name)

def calculate_uniqeness_score(
    k_histogram: Dict[str, int],
):
    u_f = 0.0

    u_f_numerator = 0.0
    u_f_denominator = 0.0

    for k, count in k_histogram.items():
        u_f_numerator += count/k
        u_f_denominator += count

    u_f = u_f_numerator / u_f_denominator if u_f_denominator > 0 else 0.0
    return u_f
