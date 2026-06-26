from typing import List, Dict, Any, Hashable
from src.derandomization.common import get_field_value_from_req, normalize_value
from collections import defaultdict

def exctract_fields_values(MACs: List[Dict[str, Any]], fields: List[str]):
#def exctract_fields_values(macs: List[Dict[str, Any]], fields: List[str]) -> Dict[str, Dict[str, list[Any]]]:
    """
    Extracts specified fields from a list of MAC address dictionaries.

    Args:
        MACs (List[Dict[str, Any]]): A list of dictionaries containing MAC address information.
        fields (List[str]): A list of field names to extract from each dictionary.

    Returns:
        List[List[Any]]: A list of lists, where each inner list contains the values of the specified fields
                         for a corresponding MAC address dictionary.
    """
    tmp = defaultdict(lambda: defaultdict(list))
    for mac in MACs:
        mac_address = mac.get("MAC")
        for pr in mac.get("PROBE_REQs", []):
            for field_name in fields:
                value = normalize_value(get_field_value_from_req(pr, field_name))
                if value is None:
                    continue
                tmp[mac_address][field_name].append(value)
    
    extracted_values: Dict[str, Dict[str, list[Any]]] = {
        mac: dict(fields_dict) for mac, fields_dict in tmp.items()
    }

    return extracted_values
