# main_analysis.py
import csv
import os
import argparse
import json
from tabulate import tabulate
from src.data_loaders.load_json import load_json
from src.data_loaders.load_pcap import load_pcap
from src.metrics import value_to_label
import src.metrics.field_stats as field_stats
import src.metrics.device_stats as device_stats
import src.metrics.common as common
import src.metrics.cardinality as card
from typing import Counter
from src.metrics.value_to_label import calc_value_to_label
from src.visualization.file_output import save_txt_report
from src.visualization.plots import plot_device_value_heatmap, plot_entropy_mi_per_field, plot_global_distribution, plot_k_summary, plot_per_device_cardinality, plot_unique_devices_percent_per_field



def main():
    BASE_INPUT_DIR = os.path.normpath(
        os.path.join(os.path.dirname(__file__),"..", "..", "dataset")
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", "-d",  default="", help="Subdirectory within dataset")
    parser.add_argument("--input-type", "-i", choices=["json", "pcap"], default="pcap")
    parser.add_argument("--labeled", "-l", action="store_true")
    parser.add_argument("--label-from", choices=["folder", "file"], default="folder")
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--field", "-f", type=str, default=None)
    parser.add_argument("--full-analysis", "-a", action="store_true", help="Run full analysis (all metrics and plots)")
    args = parser.parse_args()

    INPUT_DIR = os.path.normpath(os.path.join(BASE_INPUT_DIR, args.input_dir))
    
    print("Using directory:", INPUT_DIR)

    # buffor for report lines    
    output_lines = []

    def log(msg: str = ""):
        print(msg)
        output_lines.append(msg)

    if args.input_type == "json":
        df = load_json(INPUT_DIR)
    else:
        df = load_pcap(
            INPUT_DIR,
            labeled=args.labeled,
            label_from=args.label_from,
            workers=args.workers,
        )

    # with open(os.path.join(os.path.dirname(__file__), f"../../outputs/devices/devices_{args.input_dir}.json"), "w", encoding="utf-8") as f:
    #     json.dump(df, f, ensure_ascii=False, indent=2)



    # === FIELDS COUNT ===
    total_fields_count = field_stats.count_fields_occurrences(df)
    print(f"Total occurrences of fields: {total_fields_count}")

    if args.field is not None and args.full_analysis == True:
        
        # === AFFECTED DEVICES ===
        affected = device_stats.count_affected_devices(df, args.field)
        log(f"Affected devices: {affected}")
        affected_pct = device_stats.calculate_affected_device_percentage(df, args.field)
        log(f"Affected devices (%): {affected_pct:.2f}%")

        # === STABILITY ===
        stability, devices_stabilities = field_stats.field_stability(df, args.field)
        log(f"Field stability: {stability:.2f}")
        log("Per-device stability:")
        for device, device_stability in devices_stabilities.items():
            log(f"  {device}: {device_stability:.2f}")

        # === CALCULATING ENTROPY ===
        value_entropy, entropy = field_stats.calculate_field_entropy(df, args.field)
        log(f"Total entropy of the field: {round(entropy, 2)}")

        per_device_entropy, device_entropy = device_stats.calculate_device_entropy(df)
        log(f"Entropy of devices: {round(device_entropy, 2)}")
        
        # === CONDITIONAL ENTROPY ===
        conditional_entropy_XY = device_stats.calculate_global_conditional_entropy_H_XY(df, args.field)
        log(f"Conditional entropy (condition: device): {round(conditional_entropy_XY, 2)}")
        conditional_entropy_YX = device_stats.calculate_global_conditional_entropy_H_YX(df, args.field)
        log(f"Conditional entropy (condition: field value): {round(conditional_entropy_YX, 2)}")

        # === MUTUAL INFORMATION ===
        mutual_information = device_stats.calculate_mutual_information(df, args.field)
        log(f"Mutual information: {round(mutual_information, 2)}")
        normalized_mi = device_stats.calculate_normalized_mutual_information(df, args.field, entropy, device_entropy)
        log(f"Normalized mutual information: {round(normalized_mi, 2)}")
        
        # === CALCULATING DISTRIBUTION ===
        dist_counts = field_stats.calculate_field_distribution(df, args.field, normalize=False)
        dist_probs  = field_stats.calculate_field_distribution(df, args.field, normalize=True)

        log("\nDISTRIBUTION (number of frames)")
        for v, c in sorted(dist_counts.items()):
            log(f"Value: {v}, Count: {c}, Percent: {dist_probs[v]*100:.2f}%")
        
        log("\nDISTRIBUTION (probabilities)")
        for v, p in sorted(dist_probs.items()):
            log(f"Value: {v}, Probability: {p:.4f}")

        # === PER-DEVICE DISTRIBUTION ===
        per_device_dist_counts = device_stats.calculate_per_device_distribution(df, args.field, normalize=False)

        log("\nPER-DEVICE DISTRIBUTION")
        for v, c in sorted(per_device_dist_counts.items()):
            log(f"Value: {v}, Count: {c}")

        log("\n FIELD DISTRIBUTION FOR DEVICES")
        for v, c in sorted(device_stats.device_field_distribution(df, args.field).items()):
            log(f"Device: {v}")
            for val, count in sorted(c.items()):
                log(f"  Value: {val}, Count: {count}")

        # --- K-summary: how many values have given k (how many values have a given count of devices) ---
        k_hist = Counter(per_device_dist_counts.values())

        log("\nK-summary (how many VALUES have given k):")
        for k in sorted(k_hist.keys()):
            log(f"k = {k}: {k_hist[k]} values")

        u_f = field_stats.calculate_uniqeness_score(k_hist)
        log(f"\nUniqueness score: {u_f:.2f}")

        # --- per-device perspective ---
        device_perspective = device_stats.calculate_device_k_perspective(df, args.field, per_device_dist_counts)

        total_devices = len(device_perspective)
        pct = lambda x: (x / total_devices) * 100

        unique_ks = sorted(set(device_perspective.values()))

        log("\nDEVICE perspective:")
        for k in unique_ks:
            num = sum(1 for mk in device_perspective.values() if mk <= k)
            if k == 1:
                label = "at least one UNIQUE value (k=1)"
            else:
                label = f"at least one value with k<={k}"
            log(f"Devices with {label}: {num} / {total_devices} ({pct(num):.2f}%)")


        # === CALCULATING CARDINALITY ===
        cardinality = field_stats.calculate_field_cardinality(df, args.field)
        log(f"\nGlobal cardinality: {cardinality}")

        log("\nPER-DEVICE CARDINALITY")
        device_cardinality = device_stats.calculate_per_device_cardinality(df, args.field)

        hist = card.histogram_from_cardinality(device_cardinality)
        total_devices = sum(hist.values())

        for distinct_count in sorted(hist.keys()):
            num_devices = hist[distinct_count]
            pct = (num_devices / total_devices) * 100
            log(f"{distinct_count} distinct value(s): {num_devices} devices ({pct:.2f}%)")
            
                

        # print partial entropy values for specific values
        # for val, entr in value_entropy.items():
        #     print(f"Value: {val}, Entropy: {entr}")

        base_outputs_dir = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..", "outputs")
        )

        output_path = save_txt_report(
                lines=output_lines,
                input_dir=INPUT_DIR,
                field_name=args.field,
                out_dir=os.path.join(base_outputs_dir, "reports", f"{args.input_dir}"),  
            )

        print(f"\nSaved results to {output_path}")

        plot_global_distribution(
            field_name=args.field,
            value_to_count=dist_counts,
            use_probabilities=False,
            output_path=os.path.join(base_outputs_dir, "figures", f"{args.input_dir}", f"{args.field}_global_distribution.svg"),
        )

        plot_k_summary(
            field_name=args.field,
            k_to_value_count=k_hist,
            output_path=os.path.join(base_outputs_dir, "figures", f"{args.input_dir}", f"{args.field}_k_summary.svg"),
        )

        plot_per_device_cardinality(
            field_name=args.field,
            cardinality_to_device_count=hist,
            output_path=os.path.join(base_outputs_dir, "figures", f"{args.input_dir}", f"{args.field}_per_device_cardinality.svg"),
        )

        plot_entropy_mi_per_field(
            field_name=args.field,
            entropy=entropy,
            mutual_info=mutual_information,
            cond_entropy_device=conditional_entropy_XY,
            output_path=os.path.join(
                base_outputs_dir, "figures", f"{args.input_dir}", f"{args.field}_entropy_mi.svg"
            ),
        )

        plot_unique_devices_percent_per_field(
            field_name=args.field,
            device_k=device_perspective,
            output_path=os.path.join(
                base_outputs_dir, "figures", f"{args.input_dir}", f"{args.field}_unique_devices_percent.svg"
            ),
        )

        print("Plots saved.")

    elif args.field is None and args.full_analysis == False:
        
        headers = ["Device"]
        table_data = []

        # tu trzymamy wyniki dla każdej kolumny
        field_results = {}

        headers = ["Device", "TAG", "DATA", "HT_CAP", "HT_INFO", "AMPDU", "MCS", "EXT_CAP", "HT_Tx", "ANT", "EXT", "VHT", "VENDOR", "EXT_TAG", "INT"]

        for field in total_fields_count.keys():
            field_results[field] = device_stats.calculate_per_device_cardinality(df, field)
            # np. {'dev1': 3, 'dev2': 7}

        # zbierz wszystkie device
        all_devices = set()
        for result in field_results.values():
            all_devices.update(result.keys())

        # buduj wiersze
        for device in all_devices:
            device_row = device.split("_")[1] if "_" in device else device
            row = [device_row]
            for field in total_fields_count.keys():
                value = field_results[field].get(device, 0)  # 0 jeśli brak
                row.append(value)
            table_data.append(row)

        print(headers)
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

    elif args.field is not None and args.full_analysis == False:
        values_label_mapping = calc_value_to_label(df, args.field, normalize=False)
        # for value, labels in values_label_mapping.items():
        #     print(f"{value}: {', '.join(sorted(labels))}")
        with open(f"outputs/reports/{args.input_dir}/value_to_label/{args.field}.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow(["Value", "Labels"])

            for value, labels in values_label_mapping.items():
                writer.writerow([value, ", ".join(sorted(labels))])
            

if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    main()
