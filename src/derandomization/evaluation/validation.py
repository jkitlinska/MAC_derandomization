# evaluation/validation.py

import json
import math
import os
from collections import Counter, defaultdict
from itertools import combinations

from tabulate import tabulate


NOISE_CLUSTER = -1


# ============================================================
# Helpers
# ============================================================

def _safe_int_cluster_id(cluster_id):
    """
    Attempts to convert cluster_id to int.
    Handles values such as "-1", np.int64(-1), and 3.
    If conversion is not possible, returns the original value.
    """
    try:
        return int(cluster_id)
    except Exception:
        return cluster_id


def _ensure_output_dir(path="outputs"):
    os.makedirs(path, exist_ok=True)


def _build_mappings(clustered_data, mac_to_label):
    """
    Builds the basic mappings used for validation.

    clustered_data:
        {cluster_id: [mac1, mac2, ...]}

    mac_to_label:
        {mac: true_label}

    Returns:
        mac_to_cluster
        cluster_to_macs
        label_to_macs
        labeled_macs_in_clusters
        missing_labeled_macs
        duplicate_macs
    """
    mac_to_cluster = {}
    cluster_to_macs = defaultdict(list)
    duplicate_macs = defaultdict(list)

    for cid_raw, mac_list in clustered_data.items():
        cid = _safe_int_cluster_id(cid_raw)

        for mac in mac_list:
            if mac in mac_to_cluster:
                duplicate_macs[mac].append(cid)

            mac_to_cluster[mac] = cid
            cluster_to_macs[cid].append(mac)

    label_to_macs = defaultdict(list)
    for mac, label in mac_to_label.items():
        label_to_macs[label].append(mac)

    labeled_macs_in_clusters = [
        mac for mac in mac_to_label
        if mac in mac_to_cluster
    ]

    missing_labeled_macs = [
        mac for mac in mac_to_label
        if mac not in mac_to_cluster
    ]

    return {
        "mac_to_cluster": mac_to_cluster,
        "cluster_to_macs": dict(cluster_to_macs),
        "label_to_macs": dict(label_to_macs),
        "labeled_macs_in_clusters": labeled_macs_in_clusters,
        "missing_labeled_macs": missing_labeled_macs,
        "duplicate_macs": dict(duplicate_macs),
    }


def _filter_eval_macs(labeled_macs_in_clusters, mac_to_cluster, include_noise=False):
    """
    Returns the list of labeled MACs used for quality metrics.

    include_noise=False:
        skips MACs from cluster -1.

    include_noise=True:
        also includes noise as a regular cluster.
    """
    if include_noise:
        return list(labeled_macs_in_clusters)

    return [
        mac for mac in labeled_macs_in_clusters
        if mac_to_cluster.get(mac) != NOISE_CLUSTER
    ]


def _format_pct(value):
    return f"{value * 100.0:.1f}%"


def _f1(p, r):
    return (2.0 * p * r / (p + r)) if (p + r) > 0.0 else 0.0


# ============================================================
# Main qualitative metrics
# ============================================================

def compute_cluster_purity_metrics(clustered_data, mac_to_label, include_noise=False):
    """
    Computes cluster purity.

    cluster purity:
        for each cluster, the dominant label is selected.
        cluster purity = number of MACs with the dominant label / number of labeled MACs in the cluster.

    macro_purity:
        average over clusters, where each cluster has the same weight.

    weighted_purity:
        average weighted by cluster size.
        This is qualitatively more stable than just the number of pure clusters.
    """
    maps = _build_mappings(clustered_data, mac_to_label)
    cluster_to_macs = maps["cluster_to_macs"]

    cluster_rows = []
    total_labeled = 0
    total_majority = 0
    pure_count = 0

    for cid, macs in cluster_to_macs.items():
        if cid == NOISE_CLUSTER and not include_noise:
            continue

        labels = [
            mac_to_label[mac]
            for mac in macs
            if mac in mac_to_label
        ]

        if not labels:
            continue

        counts = Counter(labels)
        majority_label, majority_count = counts.most_common(1)[0]
        cluster_size = len(labels)
        purity = majority_count / cluster_size if cluster_size else 0.0
        is_pure = len(counts) == 1

        if is_pure:
            pure_count += 1

        total_labeled += cluster_size
        total_majority += majority_count

        cluster_rows.append({
            "cluster": cid,
            "labeled_size": cluster_size,
            "majority_label": majority_label,
            "majority_count": majority_count,
            "num_labels": len(counts),
            "purity": purity,
            "is_pure": is_pure,
            "label_counts": dict(counts),
        })

    num_clusters = len(cluster_rows)
    macro_purity = (
        sum(row["purity"] for row in cluster_rows) / num_clusters
        if num_clusters else 0.0
    )
    weighted_purity = (
        total_majority / total_labeled
        if total_labeled else 0.0
    )
    pure_clusters_pct = (
        pure_count / num_clusters
        if num_clusters else 0.0
    )

    return {
        "num_clusters_with_labels": num_clusters,
        "pure_clusters": pure_count,
        "pure_clusters_pct": pure_clusters_pct,
        "macro_purity": macro_purity,
        "weighted_purity": weighted_purity,
        "cluster_rows": cluster_rows,
    }


def compute_device_fragmentation_metrics(clustered_data, mac_to_label, include_noise=False):
    """
    Computes device fragmentation.

    For each true device, checks:
        - how many clusters it was assigned to,
        - what percentage of its MACs was assigned to the largest cluster,
        - whether the whole device is in a single cluster.

    best_cluster_recall:
        largest device fragment / all device MACs present in the evaluation.

    This penalizes splitting a single device across many clusters well.
    """
    maps = _build_mappings(clustered_data, mac_to_label)
    mac_to_cluster = maps["mac_to_cluster"]
    label_to_macs = maps["label_to_macs"]

    device_rows = []
    single_cluster_count = 0
    detected_devices = 0

    for label, macs in label_to_macs.items():
        eval_macs = [
            mac for mac in macs
            if mac in mac_to_cluster
            and (include_noise or mac_to_cluster[mac] != NOISE_CLUSTER)
        ]

        if not eval_macs:
            device_rows.append({
                "label": label,
                "detected_macs": 0,
                "num_clusters": 0,
                "best_cluster": None,
                "best_cluster_count": 0,
                "best_cluster_recall": 0.0,
                "clusters": {},
                "is_single_cluster": False,
            })
            continue

        detected_devices += 1
        cluster_counts = Counter(mac_to_cluster[mac] for mac in eval_macs)
        best_cluster, best_count = cluster_counts.most_common(1)[0]
        num_clusters = len(cluster_counts)
        best_cluster_recall = best_count / len(eval_macs)
        is_single_cluster = num_clusters == 1

        if is_single_cluster:
            single_cluster_count += 1

        device_rows.append({
            "label": label,
            "detected_macs": len(eval_macs),
            "num_clusters": num_clusters,
            "best_cluster": best_cluster,
            "best_cluster_count": best_count,
            "best_cluster_recall": best_cluster_recall,
            "clusters": dict(cluster_counts),
            "is_single_cluster": is_single_cluster,
        })

    total_devices = len(label_to_macs)
    detected_devices_pct = detected_devices / total_devices if total_devices else 0.0
    single_cluster_pct_all = single_cluster_count / total_devices if total_devices else 0.0
    single_cluster_pct_detected = (
        single_cluster_count / detected_devices
        if detected_devices else 0.0
    )

    recalls = [
        row["best_cluster_recall"]
        for row in device_rows
        if row["detected_macs"] > 0
    ]
    macro_best_cluster_recall = (
        sum(recalls) / len(recalls)
        if recalls else 0.0
    )

    weighted_best_cluster_recall = (
        sum(row["best_cluster_recall"] * row["detected_macs"] for row in device_rows)
        / sum(row["detected_macs"] for row in device_rows)
        if sum(row["detected_macs"] for row in device_rows) > 0
        else 0.0
    )

    return {
        "total_devices": total_devices,
        "detected_devices": detected_devices,
        "detected_devices_pct": detected_devices_pct,
        "single_cluster_devices": single_cluster_count,
        "single_cluster_pct_all": single_cluster_pct_all,
        "single_cluster_pct_detected": single_cluster_pct_detected,
        "macro_best_cluster_recall": macro_best_cluster_recall,
        "weighted_best_cluster_recall": weighted_best_cluster_recall,
        "device_rows": device_rows,
    }


def compute_majority_assignment_accuracy(clustered_data, mac_to_label, include_noise=False):
    """
    Computes accuracy based on the dominant label in each cluster.

    For each cluster:
        majority_label = the most frequent label in the cluster.
    A MAC is correct if its label == majority_label.

    This is more natural as "cluster-majority accuracy" than the previous version,
    which selected the expected cluster separately for each device.
    """
    maps = _build_mappings(clustered_data, mac_to_label)
    cluster_to_macs = maps["cluster_to_macs"]

    correct = 0
    incorrect = 0
    incorrect_macs = []

    for cid, macs in cluster_to_macs.items():
        if cid == NOISE_CLUSTER and not include_noise:
            continue

        labeled_macs = [
            mac for mac in macs
            if mac in mac_to_label
        ]

        if not labeled_macs:
            continue

        label_counts = Counter(mac_to_label[mac] for mac in labeled_macs)
        majority_label, majority_count = label_counts.most_common(1)[0]

        for mac in labeled_macs:
            true_label = mac_to_label[mac]
            if true_label == majority_label:
                correct += 1
            else:
                incorrect += 1
                incorrect_macs.append({
                    "MAC": mac,
                    "label": true_label,
                    "cluster": cid,
                    "expected_label_for_cluster": majority_label,
                    "cluster_label_counts": dict(label_counts),
                })

    total = correct + incorrect
    accuracy = correct / total if total else 0.0

    return {
        "correct": correct,
        "incorrect": incorrect,
        "total": total,
        "accuracy": accuracy,
        "incorrect_macs": incorrect_macs,
    }


def compute_pairwise_metrics(clustered_data, mac_to_label, include_noise=False):
    """
    Pairwise precision/recall/F1.

    TP:
        a pair of MACs with the same label and the same cluster.

    FP:
        a pair of MACs with different labels but the same cluster.

    FN:
        a pair of MACs with the same label but different clusters.

    This metric is very useful here:
        - precision penalizes mixing devices,
        - recall penalizes splitting one device across many clusters.
    """
    maps = _build_mappings(clustered_data, mac_to_label)
    mac_to_cluster = maps["mac_to_cluster"]

    eval_macs = _filter_eval_macs(
        maps["labeled_macs_in_clusters"],
        mac_to_cluster,
        include_noise=include_noise,
    )

    if len(eval_macs) < 2:
        return {
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
        }

    # Compute TP + FP from clusters.
    cluster_label_counts = defaultdict(Counter)
    for mac in eval_macs:
        cid = mac_to_cluster[mac]
        label = mac_to_label[mac]
        cluster_label_counts[cid][label] += 1

    tp = 0
    fp = 0

    for counts in cluster_label_counts.values():
        cluster_size = sum(counts.values())
        same_label_pairs = sum(n * (n - 1) // 2 for n in counts.values())
        all_cluster_pairs = cluster_size * (cluster_size - 1) // 2

        tp += same_label_pairs
        fp += all_cluster_pairs - same_label_pairs

    # Compute FN from true classes.
    label_cluster_counts = defaultdict(Counter)
    for mac in eval_macs:
        label = mac_to_label[mac]
        cid = mac_to_cluster[mac]
        label_cluster_counts[label][cid] += 1

    total_same_label_pairs = 0
    for counts in label_cluster_counts.values():
        label_size = sum(counts.values())
        total_same_label_pairs += label_size * (label_size - 1) // 2

    fn = total_same_label_pairs - tp

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": _f1(precision, recall),
    }


def compute_bcubed_metrics(clustered_data, mac_to_label, include_noise=False):
    """
    B-cubed precision/recall/F1.

    For each MAC:
        precision_i = number of MACs in its cluster with the same label / cluster size
        recall_i = number of MACs with its label in its cluster / label size

    Then the values are averaged over MACs.

    This shows local per-element quality well.
    """
    maps = _build_mappings(clustered_data, mac_to_label)
    mac_to_cluster = maps["mac_to_cluster"]

    eval_macs = _filter_eval_macs(
        maps["labeled_macs_in_clusters"],
        mac_to_cluster,
        include_noise=include_noise,
    )

    if not eval_macs:
        return {
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "N": 0,
        }

    cluster_label_counts = defaultdict(Counter)
    label_cluster_counts = defaultdict(Counter)
    label_counts = Counter()

    for mac in eval_macs:
        cid = mac_to_cluster[mac]
        label = mac_to_label[mac]

        cluster_label_counts[cid][label] += 1
        label_cluster_counts[label][cid] += 1
        label_counts[label] += 1

    precision_sum = 0.0
    recall_sum = 0.0

    for mac in eval_macs:
        cid = mac_to_cluster[mac]
        label = mac_to_label[mac]

        cluster_size = sum(cluster_label_counts[cid].values())
        label_size = label_counts[label]
        same_in_cluster = cluster_label_counts[cid][label]

        precision_sum += same_in_cluster / cluster_size if cluster_size else 0.0
        recall_sum += same_in_cluster / label_size if label_size else 0.0

    precision = precision_sum / len(eval_macs)
    recall = recall_sum / len(eval_macs)

    return {
        "precision": precision,
        "recall": recall,
        "f1": _f1(precision, recall),
        "N": len(eval_macs),
    }


def compute_dcms_metrics(clustered_data, mac_to_label, include_noise=False):
    """
    DCMS in two directions.

    1. cluster_best:
        for each cluster, the best device is selected.
        Measures cluster purity and how well the cluster matches the device.

    2. device_best:
        for each device, the best cluster is selected.
        Measures whether the device is well covered by a single cluster.

    DCMS is F1 with:
        precision = |C ∩ D| / |C|
        recall    = |C ∩ D| / |D|
    """
    maps = _build_mappings(clustered_data, mac_to_label)
    cluster_to_macs = maps["cluster_to_macs"]
    label_to_macs = maps["label_to_macs"]
    mac_to_cluster = maps["mac_to_cluster"]

    eval_macs = set(_filter_eval_macs(
        maps["labeled_macs_in_clusters"],
        mac_to_cluster,
        include_noise=include_noise,
    ))

    cluster_to_labeled = {}
    for cid, macs in cluster_to_macs.items():
        if cid == NOISE_CLUSTER and not include_noise:
            continue

        s = set(mac for mac in macs if mac in eval_macs)
        if s:
            cluster_to_labeled[cid] = s

    device_to_macs = {}
    for label, macs in label_to_macs.items():
        s = set(mac for mac in macs if mac in eval_macs)
        if s:
            device_to_macs[label] = s

    def pair_score(cluster_macs, device_macs):
        inter = cluster_macs & device_macs
        inter_size = len(inter)

        if inter_size == 0:
            return 0.0, 0.0, 0.0, 0

        precision = inter_size / len(cluster_macs) if cluster_macs else 0.0
        recall = inter_size / len(device_macs) if device_macs else 0.0
        f1 = _f1(precision, recall)

        return f1, precision, recall, inter_size

    cluster_best = {}
    perfect_cluster_matches = 0

    for cid, c_macs in cluster_to_labeled.items():
        best = {
            "dcms": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "best_label": None,
            "intersection": 0,
            "cluster_size": len(c_macs),
            "device_size": 0,
        }

        for label, d_macs in device_to_macs.items():
            f1, p, r, inter = pair_score(c_macs, d_macs)
            if f1 > best["dcms"]:
                best = {
                    "dcms": f1,
                    "precision": p,
                    "recall": r,
                    "best_label": label,
                    "intersection": inter,
                    "cluster_size": len(c_macs),
                    "device_size": len(d_macs),
                }

        if (
            best["dcms"] == 1.0
            and best["intersection"] == best["cluster_size"] == best["device_size"]
        ):
            perfect_cluster_matches += 1

        cluster_best[cid] = best

    device_best = {}
    perfect_device_matches = 0

    for label, d_macs in device_to_macs.items():
        best = {
            "dcms": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "best_cluster": None,
            "intersection": 0,
            "cluster_size": 0,
            "device_size": len(d_macs),
        }

        for cid, c_macs in cluster_to_labeled.items():
            f1, p, r, inter = pair_score(c_macs, d_macs)
            if f1 > best["dcms"]:
                best = {
                    "dcms": f1,
                    "precision": p,
                    "recall": r,
                    "best_cluster": cid,
                    "intersection": inter,
                    "cluster_size": len(c_macs),
                    "device_size": len(d_macs),
                }

        if (
            best["dcms"] == 1.0
            and best["intersection"] == best["cluster_size"] == best["device_size"]
        ):
            perfect_device_matches += 1

        device_best[label] = best

    def aggregate_cluster_scores(scores):
        valid = list(scores.values())
        if not valid:
            return 0.0, 0.0

        macro = sum(s["dcms"] for s in valid) / len(valid)

        total_weight = sum(s["cluster_size"] for s in valid)
        weighted = (
            sum(s["dcms"] * s["cluster_size"] for s in valid) / total_weight
            if total_weight else 0.0
        )

        return macro, weighted

    def aggregate_device_scores(scores):
        valid = list(scores.values())
        if not valid:
            return 0.0, 0.0

        macro = sum(s["dcms"] for s in valid) / len(valid)

        total_weight = sum(s["device_size"] for s in valid)
        weighted = (
            sum(s["dcms"] * s["device_size"] for s in valid) / total_weight
            if total_weight else 0.0
        )

        return macro, weighted

    cluster_macro, cluster_weighted = aggregate_cluster_scores(cluster_best)
    device_macro, device_weighted = aggregate_device_scores(device_best)

    return {
        "cluster_best": cluster_best,
        "device_best": device_best,
        "cluster_macro": cluster_macro,
        "cluster_weighted": cluster_weighted,
        "device_macro": device_macro,
        "device_weighted": device_weighted,
        "perfect_cluster_matches": perfect_cluster_matches,
        "perfect_device_matches": perfect_device_matches,
    }


def compute_sklearn_external_metrics(clustered_data, mac_to_label, include_noise=False):
    """
    Additional metrics from sklearn:
        - ARI: Adjusted Rand Index
        - AMI: Adjusted Mutual Information
        - NMI: Normalized Mutual Information
        - homogeneity
        - completeness
        - V-measure

    ARI is usually more sensitive to real differences in partitions than V-measure alone.
    """
    try:
        from sklearn.metrics import (
            adjusted_mutual_info_score,
            adjusted_rand_score,
            completeness_score,
            homogeneity_score,
            normalized_mutual_info_score,
            v_measure_score,
        )
    except Exception as e:
        return {
            "available": False,
            "error": str(e),
        }

    maps = _build_mappings(clustered_data, mac_to_label)
    mac_to_cluster = maps["mac_to_cluster"]

    eval_macs = _filter_eval_macs(
        maps["labeled_macs_in_clusters"],
        mac_to_cluster,
        include_noise=include_noise,
    )

    y_true = [mac_to_label[mac] for mac in eval_macs]
    y_pred = [mac_to_cluster[mac] for mac in eval_macs]

    if not y_true:
        return {
            "available": True,
            "N": 0,
            "ari": float("nan"),
            "ami": float("nan"),
            "nmi": float("nan"),
            "homogeneity": float("nan"),
            "completeness": float("nan"),
            "v_measure": float("nan"),
        }

    return {
        "available": True,
        "N": len(y_true),
        "num_classes": len(set(y_true)),
        "num_clusters": len(set(y_pred)),
        "ari": adjusted_rand_score(y_true, y_pred),
        "ami": adjusted_mutual_info_score(y_true, y_pred),
        "nmi": normalized_mutual_info_score(y_true, y_pred),
        "homogeneity": homogeneity_score(y_true, y_pred),
        "completeness": completeness_score(y_true, y_pred),
        "v_measure": v_measure_score(y_true, y_pred, beta=1.0),
    }


# ============================================================
# Report
# ============================================================

def display_report(clustered_data, mac_to_label, include_noise_in_quality=False):
    """
    Main quality report.

    By default, include_noise_in_quality=False:
        noise is reported separately, but is not included in cluster quality.
        This is usually better because noise=-1 is not a real device cluster.
    """
    maps = _build_mappings(clustered_data, mac_to_label)
    mac_to_cluster = maps["mac_to_cluster"]
    label_to_macs = maps["label_to_macs"]
    labeled_macs_in_clusters = maps["labeled_macs_in_clusters"]
    missing_labeled_macs = maps["missing_labeled_macs"]
    duplicate_macs = maps["duplicate_macs"]

    total_labeled = len(mac_to_label)
    total_labeled_in_clusters = len(labeled_macs_in_clusters)

    labeled_noise_macs = [
        mac for mac in labeled_macs_in_clusters
        if mac_to_cluster.get(mac) == NOISE_CLUSTER
    ]
    noise_count = len(labeled_noise_macs)
    noise_pct_all = noise_count / total_labeled if total_labeled else 0.0
    noise_pct_clustered = (
        noise_count / total_labeled_in_clusters
        if total_labeled_in_clusters else 0.0
    )

    missing_count = len(missing_labeled_macs)
    missing_pct = missing_count / total_labeled if total_labeled else 0.0

    majority_acc = compute_majority_assignment_accuracy(
        clustered_data,
        mac_to_label,
        include_noise=include_noise_in_quality,
    )
    purity = compute_cluster_purity_metrics(
        clustered_data,
        mac_to_label,
        include_noise=include_noise_in_quality,
    )
    fragmentation = compute_device_fragmentation_metrics(
        clustered_data,
        mac_to_label,
        include_noise=include_noise_in_quality,
    )
    pairwise = compute_pairwise_metrics(
        clustered_data,
        mac_to_label,
        include_noise=include_noise_in_quality,
    )
    bcubed = compute_bcubed_metrics(
        clustered_data,
        mac_to_label,
        include_noise=include_noise_in_quality,
    )
    dcms = compute_dcms_metrics(
        clustered_data,
        mac_to_label,
        include_noise=include_noise_in_quality,
    )
    sklearn_metrics = compute_sklearn_external_metrics(
        clustered_data,
        mac_to_label,
        include_noise=include_noise_in_quality,
    )

    print("\n--- CLUSTER VALIDATION ---")
    print(f"Total labeled MACs: {total_labeled}")
    print(f"Labeled MACs present in clustered_data: {total_labeled_in_clusters}")
    print(f"Labeled MACs missing from clustered_data: {missing_count} ({_format_pct(missing_pct)})")

    if duplicate_macs:
        print(f"WARNING: found MACs assigned to more than one cluster: {len(duplicate_macs)}")
    else:
        print("Duplicate MACs across clusters: none")

    print("\n--- NOISE ---")
    print(
        f"Labeled MACs in noise (-1): {noise_count} "
        f"({_format_pct(noise_pct_all)} of all labeled MACs, "
        f"{_format_pct(noise_pct_clustered)} present in clustered_data)"
    )

    quality_scope = "including noise" if include_noise_in_quality else "without noise"
    print(f"\n--- QUALITY METRICS ({quality_scope}) ---")

    print("\n[1] Cluster-majority accuracy / weighted purity")
    print(f"Correct by cluster majority label: {majority_acc['correct']}")
    print(f"Incorrect by cluster majority label: {majority_acc['incorrect']}")
    print(f"Total analyzed MACs: {majority_acc['total']}")
    print(f"Accuracy: {majority_acc['accuracy']:.3f}")

    print("\n[2] Cluster purity")
    print(f"Clusters with labeled MACs: {purity['num_clusters_with_labels']}")
    print(
        f"Pure clusters: {purity['pure_clusters']} "
        f"({_format_pct(purity['pure_clusters_pct'])})"
    )
    print(f"Purity macro: {purity['macro_purity']:.3f}")
    print(f"Purity weighted by |C|: {purity['weighted_purity']:.3f}")

    print("\n[3] Device fragmentation")
    print(f"Total devices: {fragmentation['total_devices']}")
    print(
        f"Detected devices: {fragmentation['detected_devices']} "
        f"({_format_pct(fragmentation['detected_devices_pct'])})"
    )
    print(
        f"Devices in a single cluster: {fragmentation['single_cluster_devices']}/"
        f"{fragmentation['total_devices']} "
        f"({_format_pct(fragmentation['single_cluster_pct_all'])} of all, "
        f"{_format_pct(fragmentation['single_cluster_pct_detected'])} detected)"
    )
    print(f"Best-cluster recall macro: {fragmentation['macro_best_cluster_recall']:.3f}")
    print(f"Best-cluster recall weighted by |D|: {fragmentation['weighted_best_cluster_recall']:.3f}")

    print("\n[4] Pairwise metrics")
    print(f"Pairwise precision: {pairwise['precision']:.3f}")
    print(f"Pairwise recall:    {pairwise['recall']:.3f}")
    print(f"Pairwise F1:        {pairwise['f1']:.3f}")
    print(f"TP={pairwise['tp']}  FP={pairwise['fp']}  FN={pairwise['fn']}")

    print("\n[5] B-cubed metrics")
    print(f"B-cubed precision: {bcubed['precision']:.3f}")
    print(f"B-cubed recall:    {bcubed['recall']:.3f}")
    print(f"B-cubed F1:        {bcubed['f1']:.3f}")
    print(f"N={bcubed['N']}")

    print("\n[6] DCMS")
    print(f"Cluster-best DCMS macro: {dcms['cluster_macro']:.3f}")
    print(f"Cluster-best DCMS weighted by |C|: {dcms['cluster_weighted']:.3f}")
    print(f"Device-best DCMS macro: {dcms['device_macro']:.3f}")
    print(f"Device-best DCMS weighted by |D|: {dcms['device_weighted']:.3f}")
    print(f"Perfect clusters: {dcms['perfect_cluster_matches']}")
    print(f"Perfectly recognized devices: {dcms['perfect_device_matches']}")

    print("\n[7] Sklearn external metrics")
    if sklearn_metrics.get("available"):
        print(f"N={sklearn_metrics['N']}")
        print(f"ARI:          {sklearn_metrics['ari']:.3f}")
        print(f"AMI:          {sklearn_metrics['ami']:.3f}")
        print(f"NMI:          {sklearn_metrics['nmi']:.3f}")
        print(f"Homogeneity:  {sklearn_metrics['homogeneity']:.3f}")
        print(f"Completeness: {sklearn_metrics['completeness']:.3f}")
        print(f"V-measure:    {sklearn_metrics['v_measure']:.3f}")
    else:
        print("sklearn is missing or an import error occurred.")
        print(f"Details: {sklearn_metrics.get('error')}")

    # Worst clusters by purity.
    worst_clusters = sorted(
        purity["cluster_rows"],
        key=lambda row: (row["purity"], -row["labeled_size"]),
    )[:10]

    if worst_clusters:
        print("\n--- WORST CLUSTERS BY PURITY ---")
        table = []
        for row in worst_clusters:
            label_counts = ", ".join(
                f"{label}:{count}"
                for label, count in sorted(row["label_counts"].items())
            )
            table.append([
                row["cluster"],
                row["labeled_size"],
                row["majority_label"],
                row["majority_count"],
                row["num_labels"],
                f"{row['purity']:.3f}",
                label_counts,
            ])

        print(tabulate(
            table,
            headers=[
                "Cluster",
                "|C| labeled",
                "Majority label",
                "Majority count",
                "#labels",
                "Purity",
                "Label counts",
            ],
            tablefmt="grid",
        ))

    # Most fragmented devices.
    fragmented_devices = sorted(
        [
            row for row in fragmentation["device_rows"]
            if row["detected_macs"] > 0
        ],
        key=lambda row: (-row["num_clusters"], row["best_cluster_recall"]),
    )[:10]

    if fragmented_devices:
        print("\n--- MOST FRAGMENTED DEVICES ---")
        table = []
        for row in fragmented_devices:
            clusters_str = ", ".join(
                f"{cid}:{count}"
                for cid, count in sorted(row["clusters"].items(), key=lambda x: str(x[0]))
            )
            table.append([
                row["label"],
                row["detected_macs"],
                row["num_clusters"],
                row["best_cluster"],
                row["best_cluster_count"],
                f"{row['best_cluster_recall']:.3f}",
                clusters_str,
            ])

        print(tabulate(
            table,
            headers=[
                "Label",
                "MACs",
                "#clusters",
                "Best cluster",
                "Best count",
                "Best recall",
                "Clusters(counts)",
            ],
            tablefmt="grid",
        ))

    # Lowest cluster-side DCMS.
    worst_dcms_clusters = sorted(
        dcms["cluster_best"].items(),
        key=lambda item: item[1]["dcms"],
    )[:10]

    if worst_dcms_clusters:
        print("\n--- LOWEST CLUSTER-BEST DCMS ---")
        for cid, s in worst_dcms_clusters:
            print(
                f"Cluster {cid}: "
                f"DCMS={s['dcms']:.3f}, "
                f"P={s['precision']:.3f}, "
                f"R={s['recall']:.3f}, "
                f"best_label={s['best_label']}, "
                f"|C∩D|={s['intersection']}, "
                f"|C|={s['cluster_size']}, "
                f"|D|={s['device_size']}"
            )

    # Lowest device-side DCMS.
    worst_dcms_devices = sorted(
        dcms["device_best"].items(),
        key=lambda item: item[1]["dcms"],
    )[:10]

    if worst_dcms_devices:
        print("\n--- LOWEST DEVICE-BEST DCMS ---")
        for label, s in worst_dcms_devices:
            print(
                f"Device {label}: "
                f"DCMS={s['dcms']:.3f}, "
                f"P={s['precision']:.3f}, "
                f"R={s['recall']:.3f}, "
                f"best_cluster={s['best_cluster']}, "
                f"|C∩D|={s['intersection']}, "
                f"|C|={s['cluster_size']}, "
                f"|D|={s['device_size']}"
            )

    # Save incorrect assignments.
    incorrect_macs = majority_acc["incorrect_macs"]
    if incorrect_macs:
        _ensure_output_dir("outputs")
        with open("outputs/incorrect_macs.json", "w", encoding="utf-8") as f:
            json.dump(incorrect_macs, f, indent=2, ensure_ascii=False)

        print("\nSaved incorrectly classified MACs to file: outputs/incorrect_macs.json")

    # Device -> clusters table with counts.
    print("\n--- DEVICES AND CLUSTERS ---")

    table_data = []
    for row in sorted(fragmentation["device_rows"], key=lambda x: x["label"]):
        clusters = row["clusters"]
        clusters_str = ", ".join(
            f"{cid}:{count}"
            for cid, count in sorted(clusters.items(), key=lambda x: str(x[0]))
        ) if clusters else "-"

        table_data.append([
            row["label"],
            row["detected_macs"],
            row["num_clusters"],
            row["best_cluster"] if row["best_cluster"] is not None else "-",
            f"{row['best_cluster_recall']:.3f}",
            clusters_str,
        ])

    print(tabulate(
        table_data,
        headers=[
            "Label",
            "MACs Detected",
            "Clusters Detected",
            "Best Cluster",
            "Best Recall",
            "Clusters(counts)",
        ],
        tablefmt="grid",
    ))


# ============================================================
# V-measure implementation
# ============================================================

def _entropy_from_counts(counts_dict, total):
    """
    Shannon entropy in nats.
    The logarithm base does not matter for V-measure because ratios are used.
    """
    if total <= 0:
        return 0.0

    return -sum(
        (n / total) * math.log(n / total)
        for n in counts_dict.values()
        if n > 0
    )


def _conditional_entropy_C_given_K(C_counts, K_counts, CK_counts, N):
    """
    H(C|K) = sum_k p(k) * H(C|k)
    """
    if N <= 0:
        return 0.0

    H = 0.0

    for k, nk in K_counts.items():
        if nk <= 0:
            continue

        H_Ck = 0.0

        for c in C_counts.keys():
            n_ck = CK_counts.get((k, c), 0)
            if n_ck:
                p = n_ck / nk
                H_Ck -= p * math.log(p)

        H += (nk / N) * H_Ck

    return H


def _conditional_entropy_K_given_C(C_counts, K_counts, CK_counts, N):
    """
    H(K|C) = sum_c p(c) * H(K|c)
    """
    if N <= 0:
        return 0.0

    H = 0.0

    for c, nc in C_counts.items():
        if nc <= 0:
            continue

        H_Kc = 0.0

        for k in K_counts.keys():
            n_ck = CK_counts.get((k, c), 0)
            if n_ck:
                p = n_ck / nc
                H_Kc -= p * math.log(p)

        H += (nc / N) * H_Kc

    return H


def compute_v_measure(
    clustered_data,
    mac_to_label,
    include_unlabeled=False,
    unlabeled_class="__UNK__",
    include_noise=True,
    beta=1.0,
):
    """
    Computes:
        - homogeneity
        - completeness
        - V-measure
        - VI, i.e. Variation of Information

    Parameters:
        include_unlabeled:
            if True, MACs without a label are treated as the __UNK__ class.

        include_noise:
            if False, cluster -1 is skipped.

    Classic sklearn variant:
        include_unlabeled=False
        include_noise=True or False, depending on whether you want to treat -1 as a cluster.
    """
    pairs = []

    for cid_raw, mac_list in clustered_data.items():
        k = _safe_int_cluster_id(cid_raw)

        if k == NOISE_CLUSTER and not include_noise:
            continue

        for mac in mac_list:
            if mac in mac_to_label:
                pairs.append((k, mac_to_label[mac]))
            elif include_unlabeled:
                pairs.append((k, unlabeled_class))

    N = len(pairs)

    if N == 0:
        return {
            "N": 0,
            "h": float("nan"),
            "c": float("nan"),
            "v": float("nan"),
            "beta": beta,
            "H_C": 0.0,
            "H_K": 0.0,
            "H_C_given_K": 0.0,
            "H_K_given_C": 0.0,
            "VI": 0.0,
            "num_classes": 0,
            "num_clusters": 0,
            "include_unlabeled": include_unlabeled,
            "include_noise": include_noise,
        }

    K_counts = Counter(k for k, _ in pairs)
    C_counts = Counter(c for _, c in pairs)

    CK_counts = defaultdict(int)
    for k, c in pairs:
        CK_counts[(k, c)] += 1

    H_C = _entropy_from_counts(C_counts, N)
    H_K = _entropy_from_counts(K_counts, N)
    H_C_given_K = _conditional_entropy_C_given_K(C_counts, K_counts, CK_counts, N)
    H_K_given_C = _conditional_entropy_K_given_C(C_counts, K_counts, CK_counts, N)

    h = 1.0 if H_C == 0.0 else 1.0 - (H_C_given_K / H_C)
    c = 1.0 if H_K == 0.0 else 1.0 - (H_K_given_C / H_K)

    denominator = beta * h + c
    v = 0.0 if denominator == 0.0 else (1.0 + beta) * h * c / denominator

    VI = H_C_given_K + H_K_given_C

    return {
        "N": N,
        "h": h,
        "c": c,
        "v": v,
        "beta": beta,
        "H_C": H_C,
        "H_K": H_K,
        "H_C_given_K": H_C_given_K,
        "H_K_given_C": H_K_given_C,
        "VI": VI,
        "num_classes": len(C_counts),
        "num_clusters": len(K_counts),
        "include_unlabeled": include_unlabeled,
        "include_noise": include_noise,
    }


def print_v_measure_report_simple(
    clustered_data,
    mac_to_label,
    beta=1.0,
    include_noise=True,
):
    """
    Simple V-measure report.

    By default, include_noise=True to preserve the classic behavior:
    cluster -1 is treated as a regular cluster.

    If you want a quality report without noise:
        print_v_measure_report_simple(..., include_noise=False)
    """
    res = compute_v_measure(
        clustered_data=clustered_data,
        mac_to_label=mac_to_label,
        include_unlabeled=False,
        include_noise=include_noise,
        beta=beta,
    )

    scope = "with noise=-1" if include_noise else "without noise=-1"

    print("\n--- V-MEASURE ---")
    print(f"Scope: {scope}")
    print(f"N={res['N']}, #classes={res['num_classes']}, #clusters={res['num_clusters']}")
    print(f"h={res['h']:.3f}  c={res['c']:.3f}  V-measure (β={beta})={res['v']:.3f}")
    print(f"VI={res['VI']:.3f}")


# ============================================================
# sklearn validation
# ============================================================

def validation_python(clustered_data, mac_to_label, include_noise=True):
    """
    Compares V-measure with the sklearn implementation.

    Additionally prints ARI/AMI/NMI, which usually distinguish similar results better.
    """
    try:
        from sklearn.metrics import (
            adjusted_mutual_info_score,
            adjusted_rand_score,
            completeness_score,
            homogeneity_score,
            normalized_mutual_info_score,
            v_measure_score,
        )
        sklearn_ok = True
        sklearn_err = None
    except Exception as e:
        sklearn_ok = False
        sklearn_err = e

    if not sklearn_ok:
        print("\n--- SKLEARN METRICS ---")
        print("scikit-learn is missing. Install it with: pip install scikit-learn")
        print(f"Import error details: {sklearn_err}")
        return

    maps = _build_mappings(clustered_data, mac_to_label)
    mac_to_cluster = maps["mac_to_cluster"]

    eval_macs = _filter_eval_macs(
        maps["labeled_macs_in_clusters"],
        mac_to_cluster,
        include_noise=include_noise,
    )

    y_true = [mac_to_label[mac] for mac in eval_macs]
    y_pred = [mac_to_cluster[mac] for mac in eval_macs]

    print("\n--- SKLEARN METRICS ---")
    scope = "with noise=-1" if include_noise else "without noise=-1"
    print(f"Scope: {scope}")

    if not y_true:
        print("No labeled elements available for computation.")
        return

    sk_h = homogeneity_score(y_true, y_pred)
    sk_c = completeness_score(y_true, y_pred)
    sk_v = v_measure_score(y_true, y_pred, beta=1.0)
    sk_ari = adjusted_rand_score(y_true, y_pred)
    sk_ami = adjusted_mutual_info_score(y_true, y_pred)
    sk_nmi = normalized_mutual_info_score(y_true, y_pred)

    ours = compute_v_measure(
        clustered_data=clustered_data,
        mac_to_label=mac_to_label,
        include_unlabeled=False,
        include_noise=include_noise,
        beta=1.0,
    )

    print(f"N={len(y_true)}, #classes={len(set(y_true))}, #clusters={len(set(y_pred))}")
    print(f"h={sk_h:.3f}  c={sk_c:.3f}  V-measure={sk_v:.3f}")
    print(f"ARI={sk_ari:.3f}  AMI={sk_ami:.3f}  NMI={sk_nmi:.3f}")

    dh = sk_h - ours["h"]
    dc = sk_c - ours["c"]
    dv = sk_v - ours["v"]

    print("\nV-measure comparison: sklearn - ours:")
    print(f"Δh={dh:.6f}  Δc={dc:.6f}  ΔV={dv:.6f}")