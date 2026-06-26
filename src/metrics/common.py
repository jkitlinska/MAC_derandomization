# metrics/common.py
from typing import Dict, Any, List
import json

def extract_labels(MACs: List[Dict[str, Any]]) -> List[str]:
    labels = set()
    for mac in MACs:
        label = mac.get("LABEL") if "LABEL" in mac else mac.get("MAC")
        labels.add(label)

    return list(labels)

def count_frames_in_req(req: Dict[str, Any]) -> int:
    """The number of frames that a single PROBE_REQ represents (simply len(TIME))."""
    times = req.get("TIME", [])
    return len(times) if isinstance(times, list) else 0


def count_frames_in_device(dev: Dict[str, Any]) -> int:
    """The number of frames in a single device (sum of len(TIME) across all PROBE_REQs)."""
    total = 0
    for pr in dev.get("PROBE_REQs", []):
        total += count_frames_in_req(pr)
    return total


def count_frames_in_devices(devices: List[Dict[str, Any]]) -> int:
    """The number of frames in the entire list of devices (sum of len(TIME) across all PROBE_REQs in all devices)."""
    return sum(count_frames_in_device(d) for d in devices)

def get_field_value_from_req(req, field_path):
    """
    Safely retrieves a value from PROBE_REQ.
    Supports:
      - “HT_CAP”  -> searches in req, then in req[‘DATA’][“HT_CAP”]
      - “DATA.HT_CAP”
      - nested “DATA_RTS.SUPP” type -> by default, it will also try “DATA.DATA_RTS.SUPP”
    """
    if not field_path:
        return None


    parts = field_path.split('.')
    val = req
    for p in parts:
        if isinstance(val, dict) and p in val:
            val = val[p]
        else:
            val = None
            break

    if val is not None:
        return val


    # Fallback: jeśli nie zaczyna się od "DATA.", dołóż "DATA."
    if not field_path.startswith("DATA."):
        data_path = "DATA." + field_path
        parts = data_path.split('.')
        val = req
        for p in parts:
            if isinstance(val, dict) and p in val:
                val = val[p]
            else:
                return None
        return val

    return None

def normalize_value(value):
    if value is None:
        return "NULL"

    # treating list as one characteristic
    if isinstance(value, list):
        return "[" + ",".join(map(str, value)) + "]"
    
    if isinstance(value, dict):
        return "{" + ",".join(f"{k}:{v}" for k, v in sorted(value.items())) + "}"

    return value
