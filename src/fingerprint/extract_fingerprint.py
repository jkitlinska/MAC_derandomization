from typing import List, Dict, Any, Hashable
from src.metrics.common import get_field_value_from_req, normalize_value
from collections import defaultdict

def extract_mac_fingerprints(MACs: List[Dict[str, Any]], fields: List[str]):
    """
    Extracts specified fields from a list of MAC address dictionaries.

    Args:
        MACs (List[Dict[str, Any]]): A list of dictionaries containing MAC address information.
        fields (List[str]): A list of field names to extract from each dictionary.

    Returns:
        List[List[Any]]: A list of lists, where each inner list contains the values of the specified fields
                         for a corresponding MAC address dictionary.
    """
    tmp = defaultdict(list)
    for mac in MACs:
        mac_address = mac.get("MAC")
        for pr in mac.get("PROBE_REQs", []):
            tmp_fp = []
            for field_name in fields:
                value = normalize_value(get_field_value_from_req(pr, field_name))
                if value is None:
                    continue
                tmp_fp.append(value)
                print(f"Extracted value for MAC {mac_address}, field {field_name}: {value}")
            tmp[mac_address].append(tmp_fp)
    
    extracted_values: Dict[str, list[Any]] = {
        mac: list(fields_dict) for mac, fields_dict in tmp.items()
    }
    # print (f"Extracted MAC fingerprints: {extracted_values}")

    return extracted_values

def extract_device_fingerprints(MACs: List[Dict[str, Any]], fields: List[str]):
    """
    Extracts specified fields from a list of MAC address dictionaries.

    Args:
        MACs (List[Dict[str, Any]]): A list of dictionaries containing MAC address information.
        fields (List[str]): A list of field names to extract from each dictionary.

    Returns:
        List[List[Any]]: A list of lists, where each inner list contains the values of the specified fields
                         for a corresponding MAC address dictionary.
    """

    tmp = defaultdict(list)
    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        # print(f"Processing device: {label}")
        for pr in mac.get("PROBE_REQs", []):
            tmp_fp = []
            for field_name in fields:
                value = normalize_value(get_field_value_from_req(pr, field_name))
                if value is None:
                    continue
                tmp_fp.append(value)
            tmp[label].append(tmp_fp)
    
    extracted_values: Dict[str, list[Any]] = {
        label: list(fields_dict) for label, fields_dict in tmp.items()
    }

    no_rep_fps = defaultdict(set)
    count_fp_per_device = defaultdict(int)

    for device, fps in extracted_values.items():
        unique_fps = {tuple(fp) for fp in fps}   # usuwa powtórzenia
        count_fp_per_device[device] += len(unique_fps)
        no_rep_fps[device] = unique_fps


    print (f"Number of unique fingerprints per device: {count_fp_per_device}")
    print (f"Extracted Device fingerprints: {no_rep_fps}")


    return no_rep_fps

def extract_most_common_fingerprints(MACs: List[Dict[str, Any]], fields: List[str], top_k: int = 1):
    """
    Extracts the most common fingerprints for each device based on specified fields.

    Args:
        MACs (List[Dict[str, Any]]): A list of dictionaries containing MAC address information.
        fields (List[str]): A list of field names to extract from each dictionary.
        top_k (int): The number of most common fingerprints to extract for each device.

    Returns:
        Dict[str, List[Tuple[Any, int]]]: A dictionary mapping each device label to a list of tuples,
                                          where each tuple contains a fingerprint and its count.
    """
    from collections import Counter

    device_to_fps = defaultdict(list)

    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")

        for pr in mac.get("PROBE_REQs", []):
            fp = []

            for field_name in fields:
                value = normalize_value(get_field_value_from_req(pr, field_name))

                if value is None:
                    continue

                fp.append(value)

            device_to_fps[label].append(tuple(fp))

    most_common_fingerprints = {}

    for device, fps in device_to_fps.items():
        counter = Counter(fps)

        ranked = sorted(
            counter.items(),
            key=lambda item: (-item[1], repr(item[0]))
        )

        most_common_fingerprints[device] = [
            fp for fp, _count in ranked[:top_k]
        ]

    return most_common_fingerprints