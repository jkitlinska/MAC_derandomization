from collections import defaultdict
from typing import Any, List, Dict

from src.metrics.common import get_field_value_from_req, normalize_value


def calc_value_to_label(
    MACs: List[Dict[str, Any]],
    field_name: str,
    normalize: bool = False,
) -> Dict[str, Any]:
    print(f"Calculating VALUE-TO-LABEL distribution for field '{field_name}'...")

    values = defaultdict(set)
    counts = {}

    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        label = label.split("_")[1]
        label = label[3]
        for pr in mac.get("PROBE_REQs", []):
            data = pr.get("DATA", {})
            
            raw_value = get_field_value_from_req(pr, field_name)
            value = normalize_value(raw_value)

            values[value].add(label)

    return values