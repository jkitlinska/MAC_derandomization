from contextlib import redirect_stdout
from concurrent.futures import ProcessPoolExecutor, as_completed
import argparse
import io
import json
import multiprocessing as mp
import os
import traceback

import yaml
from copy import deepcopy

import numpy as np

try:
    from tqdm import tqdm
except Exception:
    tqdm = None

from src.derandomization.evaluation.validation import (
    display_report,
    print_v_measure_report_simple,
    validation_python,
)
from src.data_loaders.load_pcap import load_pcap
from src.data_loaders.load_json import load_json
from src.derandomization.data_processing.feature_extraction import exctract_fields_values
from src.derandomization.data_processing.calculate_distance import (
    calculate_distance_matrix,
    mac_distance,
)
from src.derandomization.clustering.optics import (
    optics_clustering,
    plot_optics_reachability,
    extract_clusters,
)
from src.derandomization.common import extract_mac_to_label


# ============================================================
#  CONFIG
# ============================================================

def build_fields_cfg(weights=None):
    weights = weights or {}

    def w(name, default):
        return weights.get(name, default)

    fields_cfg = {
        "RSSI_TIME": {
            "kind": "rssi_time",
            "weight1": w("RSSI_TIME_weight1", 1.0),
            "weight2": w("RSSI_TIME_weight2", 1.0),
            "weight3": w("RSSI_TIME_weight3", 1.0),
            "weight4": w("RSSI_TIME_weight4", 1.0),
        },

        "DATA_RTS.SUPP": {
            "kind": "data_rates",
            "weight": w("DATA_RTS.SUPP", 1.0),
        },
        "DATA_RTS.EXT": {
            "kind": "data_rates",
            "weight": w("DATA_RTS.EXT", 1.0),
        },

        "HT_CAP": {
            "kind": "hex_bit",
            "weight": w("HT_CAP", 1.0),
            "penalty": 1.0,
        },
        "HT_CAP_INFO": {
            "kind": "hex_bit",
            "weight": w("HT_CAP_INFO", 1.0),
            "penalty": 1.0,
        },
        "HT_AMPDU_PARMS": {
            "kind": "hex_bit",
            "weight": w("HT_AMPDU_PARMS", 1.0),
            "penalty": 1.0,
        },
        "HT_MCS_SET": {
            "kind": "hex_bit",
            "weight": w("HT_MCS_SET", 1.0),
            "penalty": 1.0,
        },
        "HT_EXT_CAP": {
            "kind": "hex_bit",
            "weight": w("HT_EXT_CAP", 1.0),
            "penalty": 1.0,
        },
        "HT_Tx": {
            "kind": "hex_bit",
            "weight": w("HT_Tx", 1.0),
            "penalty": 1.0,
        },
        "HT_ANTENNA": {
            "kind": "hex_bit",
            "weight": w("HT_ANTENNA", 1.0),
            "penalty": 1.0,
        },
        "VHT_CAP": {
            "kind": "hex_bit",
            "weight": w("VHT_CAP", 1.0),
            "penalty": 1.0,
        },
        "EXT_CAP": {
            "kind": "hex_bit",
            "weight": w("EXT_CAP", 1.0),
            "penalty": 1.0,
        },

        "TAG_LIST": {
            "kind": "ie_list",
            "weight": w("TAG_LIST", 1.0),
            "penalty": 1.0,
        },

        "EXT_TAG": {
            "kind": "ext_tag",
            "weight1": w("EXT_TAG_weight1", 1.0),
            "weight2": w("EXT_TAG_weight2", 1.0),
            "weight3": w("EXT_TAG_weight3", 1.0),
        },

        "VENDOR_SPEC": {
            "kind": "vendor_spec",
            "weight1": w("VENDOR_SPEC_weight1", 1.0),
            "weight2": w("VENDOR_SPEC_weight2", 1.0),
            "weight3": w("VENDOR_SPEC_weight3", 1.0),
        },
    }

    return fields_cfg


ACTIVE_EXTRACT_FIELDS = [
#    "HT_CAP",
    "HT_CAP_INFO",
    "HT_AMPDU_PARMS",
    "HT_MCS_SET",
    "HT_EXT_CAP",
    "HT_Tx",
    "HT_ANTENNA",
    "TAG_LIST",
    "EXT_CAP",
    "DATA_RTS.SUPP",
    "DATA_RTS.EXT",
]


# ============================================================
#  SMALL HELPERS
# ============================================================

def iter_progress(iterable, total=None, desc=None):
    if tqdm is None:
        return iterable
    return tqdm(iterable, total=total, desc=desc)


def load_active_fields_from_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict):
        raise ValueError(f"Fields config must be a YAML dictionary: {path}")

    active_fields = config.get("active_fields")

    if not isinstance(active_fields, list):
        raise ValueError(
            f"Fields config must contain a list named 'active_fields': {path}"
        )

    active_fields = [
        field.strip()
        for field in active_fields
        if isinstance(field, str) and field.strip()
    ]

    if not active_fields:
        raise ValueError(f"No active fields found in YAML config: {path}")

    return active_fields


def make_report_name(global_scenario_name, config_name, using_weights_file):
    if using_weights_file:
        return f"{global_scenario_name}_{config_name}"
    return global_scenario_name


def set_single_weight(field_cfg, weight):
    cfg = deepcopy(field_cfg)

    if "weight" not in cfg:
        raise ValueError(f"Field cfg has no single 'weight': {cfg}")

    cfg["weight"] = float(weight)
    return cfg


def label_counts(labels):
    unique, counts = np.unique(labels, return_counts=True)
    return {int(k): int(v) for k, v in zip(unique, counts)}


def ensure_output_dirs(root_dir):
    os.makedirs(os.path.join(root_dir, "outputs"), exist_ok=True)
    os.makedirs(os.path.join(root_dir, "outputs", "reports"), exist_ok=True)
    os.makedirs(os.path.join(root_dir, "plots"), exist_ok=True)


# ============================================================
#  FAST DISTANCE MATRIX
# ============================================================

def calculate_distance_matrix_symmetric_exact(
    fields_by_mac,
    fields_cfg,
    null_token="NULL",
    desc=None,
):
    macs = list(fields_by_mac.keys())
    n = len(macs)

    matrix = np.zeros((n, n), dtype=float)

    total_pairs = n * (n + 1) // 2
    pbar = tqdm(total=total_pairs, desc=desc) if tqdm is not None and desc else None

    try:
        for i, mac1 in enumerate(macs):
            for j in range(i, n):
                mac2 = macs[j]

                dist_info = mac_distance(
                    fields_by_mac,
                    mac1,
                    mac2,
                    fields_cfg,
                    predefined_penalty = None,
                    null_token=null_token,
                )

                d = float(dist_info["total_distance"])

                matrix[i, j] = d
                matrix[j, i] = d

                if pbar is not None:
                    pbar.update(1)
    finally:
        if pbar is not None:
            pbar.close()

    return matrix


def precompute_linear_field_matrices(
    fields_by_mac,
    default_fields_cfg,
    active_fields,
    null_token="NULL",
):
    """
    Precompute per field.

    For each field, we compute two matrices:
    - const_matrix: distance when weight = 0
    - unit_matrix: distance when weight = 1

    Then:
        base_matrix = unit_matrix - const_matrix

    For the scenario:
        field_distance = const_matrix + weight * base_matrix
    """
    precomputed = {}

    fields_to_precompute = []

    for field in active_fields:
        cfg = default_fields_cfg.get(field)

        if cfg is None:
            continue

        if "weight" not in cfg:
            continue

        fields_to_precompute.append(field)

    print("\nPrecomputing per-field distance matrices...")
    print("Fields:", fields_to_precompute)

    for field in fields_to_precompute:
        cfg = default_fields_cfg[field]

        const_cfg = {
            field: set_single_weight(cfg, 0.0),
        }

        unit_cfg = {
            field: set_single_weight(cfg, 1.0),
        }

        const_matrix = calculate_distance_matrix_symmetric_exact(
            fields_by_mac=fields_by_mac,
            fields_cfg=const_cfg,
            null_token=null_token,
            desc=f"{field} const",
        )

        unit_matrix = calculate_distance_matrix_symmetric_exact(
            fields_by_mac=fields_by_mac,
            fields_cfg=unit_cfg,
            null_token=null_token,
            desc=f"{field} unit",
        )

        precomputed[field] = {
            "const": const_matrix,
            "base": unit_matrix - const_matrix,
        }

    return precomputed


def compose_distance_matrix_from_precomputed(precomputed, fields_cfg):
    """
    Compose the distance matrix for a specific scenario.
    """
    first = next(iter(precomputed.values()))
    n = first["const"].shape[0]

    matrix = np.zeros((n, n), dtype=float)

    for field, parts in precomputed.items():
        cfg = fields_cfg[field]
        weight = float(cfg.get("weight", 1.0))

        matrix += parts["const"] + weight * parts["base"]

    return matrix


def verify_precompute_equivalence(
    fields_by_mac,
    fields_cfg,
    precomputed,
    null_token="NULL",
):
    """
    Compare:
    - fast matrix with precompute
    - slow matrix with calculate_distance_matrix()
    """
    fast = compose_distance_matrix_from_precomputed(precomputed, fields_cfg)

    slow = np.array(
        calculate_distance_matrix(
            fields_by_mac, 
            fields_cfg, 
            predefined_penalty=None, 
            null_token="NULL"
        ),
        dtype=float,
    )

    diff = np.abs(fast - slow)

    return {
        "max_abs_diff": float(diff.max()),
        "mean_abs_diff": float(diff.mean()),
        "allclose": bool(np.allclose(fast, slow, rtol=1e-9, atol=1e-9)),
    }


# ============================================================
#  SCENARIO WORKER
# ============================================================

def run_one_scenario_worker(job):
    (
        cfg_entry,
        global_scenario_name,
        using_weights_file,
        macs,
        distance_matrix,
        mac_to_label,
        fields_cfg,
        root_dir,
        save_plot,
    ) = job

    report_name = make_report_name(
        global_scenario_name,
        cfg_entry.get("name", "run"),
        using_weights_file,
    )

    try:
        ensure_output_dirs(root_dir)

        model, labels = optics_clustering(distance_matrix)
        clusters = extract_clusters(model, macs)

        if save_plot:
            plot_optics_reachability(model, labels, report_name)

        clusters_without_noise = clusters.copy()
        

        if -1 in clusters_without_noise.keys():
            clusters_without_noise.pop(np.int64(-1))

        # print(f"clusters: {clusters.keys()}")
        # print(f"clusters_without_noise: {clusters_without_noise.keys()}")

        buf = io.StringIO()

        with redirect_stdout(buf):
            print("=== WEIGHTS ===")
            print(json.dumps(cfg_entry.get("weights", {}), indent=2, ensure_ascii=False))

            print("\n=== FIELDS CONFIG ===")
            print(json.dumps(fields_cfg, indent=2, ensure_ascii=False))

            print("\n=== DISTANCE MATRIX STATS ===")
            dm = np.array(distance_matrix, dtype=float)
            print(f"shape={dm.shape}")
            print(f"min={dm.min():.12f}")
            print(f"max={dm.max():.12f}")
            print(f"mean={dm.mean():.12f}")
            print(f"std={dm.std():.12f}")

            print("\n=== LABEL COUNTS ===")
            print(json.dumps(label_counts(labels), indent=2, ensure_ascii=False))

            print("\n=== REPORT ===")
            print_v_measure_report_simple(clusters, mac_to_label)
            print_v_measure_report_simple(clusters_without_noise, mac_to_label)
            display_report(clusters, mac_to_label)
            validation_python(clusters_without_noise, mac_to_label)

        report_path = os.path.join(
            root_dir,
            "outputs",
            "reports",
            f"{report_name}.txt",
        )

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(buf.getvalue())

        return {
            "ok": True,
            "report_name": report_name,
            "report_path": report_path,
            "label_counts": label_counts(labels),
        }

    except Exception:
        return {
            "ok": False,
            "report_name": report_name,
            "error": traceback.format_exc(),
        }


# ============================================================
#  MAIN
# ============================================================

def main():
    BASE_INPUT_DIR = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "../../dataset")
    )

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input-dir",
        "-d",
        default="",
        help="Subdirectory within dataset",
    )

    parser.add_argument(
        "--input-type",
        "-i",
        choices=["json", "pcap"],
        default="json",
    )

    parser.add_argument(
        "--labeled",
        "-l",
        action="store_true",
    )

    parser.add_argument(
        "--label-from",
        choices=["folder", "file"],
        default="folder",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=None,
    )

    parser.add_argument(
        "--scenario",
        "-s",
        type=str,
        default="default",
        help="Scenario name for report naming",
    )

    parser.add_argument(
        "--weights-file",
        type=str,
        default=None,
        help="JSON file with weight configurations",
    )

    parser.add_argument(
        "--configs-dir",
        type=str,
        default="configs",
        help="Path to configs directory.",
    )

    parser.add_argument(
        "--fields-config-path",
        type=str,
        default=None,
        help=(
            "Path to YAML file with active fields, e.g. "
            "configs/fields/ht_combined.yaml. "
            "If provided, it overrides --active-fields and ACTIVE_EXTRACT_FIELDS."
        ),
    )

    parser.add_argument(
        "--scenario-workers",
        type=int,
        default=max(1, (os.cpu_count() or 2) - 1),
        help="Number of parallel scenario workers.",
    )

    parser.add_argument(
        "--no-precompute",
        action="store_true",
        help="Disable per-field precompute and use old full distance calculation per scenario.",
    )

    parser.add_argument(
        "--verify-precompute",
        action="store_true",
        help="Compare precomputed matrix with old calculate_distance_matrix for the first scenario.",
    )

    parser.add_argument(
        "--save-plots",
        action="store_true",
        help="Save reachability plot. Not recommended with multiple scenario workers.",
    )
    parser.add_argument(
      "--active-fields",
      type=str,
      default=None,
      help=(
          "Comma-separated list of active fields to extract, e.g. "
          "HT_MCS_SET,HT_EXT_CAP,DATA_RTS.SUPP,DATA_RTS.EXT. "
          "If omitted, uses ACTIVE_EXTRACT_FIELDS from the script."
      ),
    )

    args = parser.parse_args()

    if args.fields_config_path:
        active_extract_fields = load_active_fields_from_yaml(args.fields_config_path)
    elif args.active_fields:
        active_extract_fields = [
            field.strip()
            for field in args.active_fields.split(",")
            if field.strip()
        ]
    else:
        active_extract_fields = ACTIVE_EXTRACT_FIELDS

    root_dir = os.getcwd()
    ensure_output_dirs(root_dir)

    input_dir = os.path.normpath(
        os.path.join(BASE_INPUT_DIR, args.input_dir)
    )

    print("Using directory:", input_dir)
    print("Root directory:", root_dir)

    if args.input_type == "json":
        df = load_json(input_dir)
    else:
        df = load_pcap(
            input_dir,
            labeled=args.labeled,
            label_from=args.label_from,
            workers=args.workers,
        )

    fields_by_mac = exctract_fields_values(df, active_extract_fields)
    mac_to_label = extract_mac_to_label(df)
    macs = list(fields_by_mac.keys())

    print(f"Loaded MACs: {len(macs)}")
    print(f"Labeled MACs: {len(mac_to_label)}")
    print("Active extracted fields:", active_extract_fields)

    if args.weights_file:
        if os.path.isabs(args.weights_file):
            weights_path = os.path.normpath(args.weights_file)
        else:
            weights_path = os.path.normpath(
                os.path.join(args.configs_dir, "weights", args.weights_file)
            )

        with open(weights_path, "r", encoding="utf-8") as f:
            weight_configs = json.load(f)
    else:
        weight_configs = [
            {
                "name": args.scenario,
                "weights": {},
            }
        ]

    using_weights_file = bool(args.weights_file)

    jobs = []

    # ------------------------------------------------------------
    #  MODE 1: full calculation per scenario
    # ------------------------------------------------------------
    if args.no_precompute:
        print("\nRunning without precompute.")
        print("Full matrix calculation per scenario.")

        for idx, cfg_entry in enumerate(weight_configs, start=1):
            config_name = cfg_entry.get("name", f"run_{idx}")
            report_name = make_report_name(
                args.scenario,
                config_name,
                using_weights_file,
            )

            fields_cfg = build_fields_cfg(
                cfg_entry.get("weights", {})
            )

            print(
                f"\nCalculating distance matrix for {report_name} "
                f"({idx}/{len(weight_configs)})..."
            )

            distance_matrix = np.array(
                calculate_distance_matrix(
                    fields_by_mac,
                    fields_cfg,
                    null_token="NULL",
                ),
                dtype=float,
            )

            jobs.append(
                (
                    cfg_entry,
                    args.scenario,
                    using_weights_file,
                    macs,
                    distance_matrix,
                    mac_to_label,
                    fields_cfg,
                    root_dir,
                    args.save_plots,
                )
            )

    # ------------------------------------------------------------
    #  MODE 2: fast precompute
    # ------------------------------------------------------------
    else:
        default_fields_cfg = build_fields_cfg({})

        precomputed = precompute_linear_field_matrices(
            fields_by_mac=fields_by_mac,
            default_fields_cfg=default_fields_cfg,
            active_fields=active_extract_fields,
            null_token="NULL",
        )

        if args.verify_precompute and weight_configs:
            print("\nVerifying precompute equivalence for the first scenario...")

            first_weights = weight_configs[0].get("weights", {})
            first_fields_cfg = build_fields_cfg(first_weights)

            verification = verify_precompute_equivalence(
                fields_by_mac=fields_by_mac,
                fields_cfg=first_fields_cfg,
                precomputed=precomputed,
                predefined_penalty=None, 
                null_token="NULL",
            )

            print(json.dumps(verification, indent=2, ensure_ascii=False))

            if not verification["allclose"]:
                raise RuntimeError(
                    "Precompute verification failed. "
                    "Use --no-precompute or inspect non-linear fields."
                )

        print("\nComposing scenario matrices...")

        iterator = iter_progress(
            weight_configs,
            total=len(weight_configs),
            desc="Compose matrices",
        )

        for cfg_entry in iterator:
            fields_cfg = build_fields_cfg(
                cfg_entry.get("weights", {})
            )

            distance_matrix = compose_distance_matrix_from_precomputed(
                precomputed,
                fields_cfg,
            )

            jobs.append(
                (
                    cfg_entry,
                    args.scenario,
                    using_weights_file,
                    macs,
                    distance_matrix,
                    mac_to_label,
                    fields_cfg,
                    root_dir,
                    args.save_plots,
                )
            )

    # ------------------------------------------------------------
    #  Run scenarios
    # ------------------------------------------------------------

    print(
        f"\nRunning {len(jobs)} scenarios "
        f"with {args.scenario_workers} worker(s)..."
    )

    results = []

    if args.scenario_workers == 1:
        iterator = iter_progress(
            jobs,
            total=len(jobs),
            desc="Scenarios",
        )

        for job in iterator:
            result = run_one_scenario_worker(job)
            results.append(result)

            if result["ok"]:
                print(
                    f"Done: {result['report_name']} "
                    f"labels={result['label_counts']}"
                )
            else:
                print(
                    f"ERROR in {result['report_name']}\n"
                    f"{result['error']}"
                )

    else:
        with ProcessPoolExecutor(max_workers=args.scenario_workers) as executor:
            future_to_name = {
                executor.submit(run_one_scenario_worker, job): job[0].get("name", "run")
                for job in jobs
            }

            futures_iter = as_completed(future_to_name)

            if tqdm is not None:
                futures_iter = tqdm(
                    futures_iter,
                    total=len(future_to_name),
                    desc="Finished scenarios",
                )

            for future in futures_iter:
                result = future.result()
                results.append(result)

                if result["ok"]:
                    msg = (
                        f"Done: {result['report_name']} "
                        f"labels={result['label_counts']}"
                    )
                else:
                    msg = (
                        f"ERROR in {result['report_name']}\n"
                        f"{result['error']}"
                    )

                if tqdm is not None:
                    tqdm.write(msg)
                else:
                    print(msg)

    summary_path = os.path.join(
        root_dir,
        "outputs",
        "reports",
        f"{args.scenario}_parallel_summary.json",
    )

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    ok_count = sum(1 for r in results if r.get("ok"))

    print(f"\nFinished: {ok_count}/{len(results)} scenarios OK")
    print(f"Summary saved to: {summary_path}")


if __name__ == "__main__":
    mp.freeze_support()
    main()