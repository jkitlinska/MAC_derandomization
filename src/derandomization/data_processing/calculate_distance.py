from itertools import product

from src.derandomization.data_processing.feature_extraction import exctract_fields_values as ext
from src.derandomization.data_processing.distances import (
    bit_dist,
    dist_data_rates,
    dist_ext_tag,
    dist_vendor_spec,
    dist_IE_list,
    dist_rssi_time
)

def effective_weight(cfg):
    if "weight" in cfg:
        return float(cfg.get("weight", 1.0))

    weight_keys = [
        k for k in cfg.keys()
        if k.startswith("weight")
    ]

    if not weight_keys:
        return 1.0

    weights = [float(cfg.get(k, 0.0)) for k in weight_keys]
    positive = [w for w in weights if w > 0.0]

    if not positive:
        return 0.0

    return sum(positive) / len(positive)

def effective_penalty(cfg, predefined_penalty):
    if predefined_penalty is not None:
        return float(cfg.get("penalty", 1.0))
    return float(cfg.get("penalty", 1.0)) * effective_weight(cfg)

def mac_distance(fields_by_mac, mac1, mac2, fields_cfg, predefined_penalty, null_token="NULL"):
    d1 = fields_by_mac.get(mac1, {})
    d2 = fields_by_mac.get(mac2, {})
    min_dist = 0.0

    per_field = {}

    for field, cfg in fields_cfg.items():
        kind = cfg["kind"]

        l1 = [v for v in (d1.get(field) or []) if v not in (null_token, None)]
        l2 = [v for v in (d2.get(field) or []) if v not in (null_token, None)]

        if not l1 and not l2:
            per_field[field] = 0.0
            continue
        if (not l1) ^ (not l2):
            # one is empty, the other is not
            per_field[field] = effective_penalty(cfg, predefined_penalty)
            continue

        if kind == "hex_bit":
            weight = float(cfg.get("weight", 1.0))
            penalty = effective_penalty(cfg, predefined_penalty)

            s = 0.0
            n = 0
            for a, b in product(l1, l2):
                if not (isinstance(a, str) and isinstance(b, str) and a.startswith("0x") and b.startswith("0x")):
                    s += penalty; n += 1; continue
                if len(a) != len(b):
                    s += penalty; n += 1; continue

                v1 = int(a, 16)
                v2 = int(b, 16)
                v1_bit = int(bin(v1)[2:], 16)
                v2_bit = int(bin(v2)[2:], 16)
                length = (len(a) - 2) * 4

                s += float(bit_dist(v1_bit, v2_bit, weight, length))
                n += 1

            per_field[field] = (s / n) if n else 0.0

        elif kind == "ie_list":
            weight = float(cfg.get("weight", 1.0))
            per_field[field] = float(dist_IE_list(l1, l2, weight))

        elif kind == "data_rates":
            weight = float(cfg.get("weight", 1.0))
            if l1 and l2 and isinstance(l1[0], (list, tuple)) and isinstance(l2[0], (list, tuple)):
                s = 0.0
                n = 0
                for a, b in product(l1, l2):
                    s += float(dist_data_rates(a, b, weight))
                    n += 1
                per_field[field] = (s / n) if n else 0.0
            else:
                per_field[field] = float(dist_data_rates(l1, l2, weight))

        elif kind == "ext_tag":
            w1 = float(cfg["weight1"]); w2 = float(cfg["weight2"]); w3 = float(cfg["weight3"])
            s = 0.0
            n = 0
            for a, b in product(l1, l2):
                s += float(dist_ext_tag(a, b, w1, w2, w3))
                n += 1
            per_field[field] = (s / n) if n else 0.0

        elif kind == "vendor_spec":
            w1 = float(cfg["weight1"]); w2 = float(cfg["weight2"]); w3 = float(cfg["weight3"])
            s = 0.0
            n = 0
            for a, b in product(l1, l2):
                s += float(dist_vendor_spec(a, b, w1, w2, w3))
                n += 1
            per_field[field] = (s / n) if n else 0.0

        elif kind == "rssi_time":
            w1 = float(cfg["weight1"]); w2 = float(cfg["weight2"])
            w3 = float(cfg["weight3"]); w4 = float(cfg["weight4"])

            # bierzemy RSSI i TIME z danych (nie z "field")
            rssi1 = [float(x) for x in (d1.get("RSSI") or []) if x not in (null_token, None)]
            time1 = [float(x) for x in (d1.get("TIME") or []) if x not in (null_token, None)]
            rssi2 = [float(x) for x in (d2.get("RSSI") or []) if x not in (null_token, None)]
            time2 = [float(x) for x in (d2.get("TIME") or []) if x not in (null_token, None)]

            if not rssi1 or not time1 or not rssi2 or not time2:
                per_field[field] = effective_penalty(cfg, predefined_penalty)
            else:
                per_field[field] = float(dist_rssi_time(rssi1, time1, rssi2, time2, w1, w2, w3, w4))


        else:
            raise ValueError(f"Unknown kind for field '{field}': {kind}")

    total_distance = sum(per_field.values())

    if total_distance < min_dist:
        total_distance = min_dist

    # print(f"Distance between {mac1} and {mac2}: {total_distance} (per field: {per_field})")

    return {
        "mac1": mac1,
        "mac2": mac2,
        "per_field": per_field,
        "total_distance": float(total_distance),
    }


def mac_distance_from_df(df, mac1, mac2, fields_cfg, null_token="NULL"):
    fields = list(fields_cfg.keys())
    fields_by_mac = ext(df, fields)
    return mac_distance(fields_by_mac, mac1, mac2, fields_cfg, null_token=null_token)


def calculate_distance_matrix(fields_by_mac, fields_cfg, predefined_penalty, null_token="NULL"):
    macs = list(fields_by_mac.keys())
    n = len(macs)
    matrix = [[None] * n for _ in range(n)]

    for i, mac1 in enumerate(macs):
        print(f"Calculating distances for {mac1} ({i+1}/{n})...")
        for j, mac2 in enumerate(macs):
            dist_info = mac_distance(fields_by_mac, mac1, mac2, fields_cfg, predefined_penalty, null_token=null_token)
            matrix[i][j] = dist_info["total_distance"]

    return matrix