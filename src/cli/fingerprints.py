#main_fingerprints.py
import os
import argparse
import json
from src.data_loaders.load_json import load_json
from src.data_loaders.load_pcap import load_pcap
from src.metrics.anonymity import fingerprint_sharing_distribution, mac_anonymity_set_size, device_anonymity_set_size
import src.fingerprint.extract_fingerprint as fingerprint
from typing import Counter
from src.visualization.file_output import save_txt_report
from src.visualization.plots import plot_anonymity_set_sizes, plot_fingerprint_sharing_distribution



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
    parser.add_argument("--fields", "-f", nargs="+", default=["HT_CAP", "VHT_CAP", "EXT_CAP"])
    parser.add_argument("--scenario", "-s", type=str, help="Scenario name for report title")
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

    base_outputs_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "outputs")
    )

    # print(df)

    mac_to_fps = fingerprint.extract_mac_fingerprints(df, args.fields)
    mac_anonymity_set_sizes = mac_anonymity_set_size(mac_to_fps)
    log(f"\nAnonymity set sizes: {mac_anonymity_set_sizes}")

    plot_anonymity_set_sizes(mac_anonymity_set_sizes, title=f"{args.input_dir} dataset MAC Anonymity Set Sizes", output_path=os.path.join(base_outputs_dir, "figures", f"{args.input_dir}", f"mac_anonymity_set_sizes_{args.scenario}.pdf"))

    device_to_fps = fingerprint.extract_most_common_fingerprints(df, args.fields)
    # print(device_to_fps)
    device_anonymity_set_sizes, fp_to_devices = device_anonymity_set_size(device_to_fps)
    log(f"\nDevice Anonymity set sizes: {device_anonymity_set_sizes}")
    # print( f"\nFingerprint to devices mapping: {fp_to_device}" )

    plot_anonymity_set_sizes(device_anonymity_set_sizes, title=f"{args.input_dir} dataset Device Anonymity Set Sizes", output_path=os.path.join(base_outputs_dir, "figures", f"{args.input_dir}", f"device_anonymity_set_sizes_{args.scenario}.pdf"))

    device_to_fps = fingerprint.extract_device_fingerprints(df, args.fields)
    fp_dist = fingerprint_sharing_distribution(device_to_fps)
    print(f"\nFingerprint to devices: {fp_to_devices}")
    log(f"\nFingerprint sharing distribution: {fp_dist}")

    plot_fingerprint_sharing_distribution(fp_dist, title=f"{args.input_dir} dataset Fingerprint Sharing Distribution", output_path=os.path.join(base_outputs_dir, "figures", f"{args.input_dir}", f"fingerprint_sharing_distribution_{args.scenario}.pdf"))

    save_txt_report(
        lines=output_lines,
        input_dir=INPUT_DIR,
        field_name=f"fingerprint_report_{args.scenario}.txt",
        out_dir=os.path.join(base_outputs_dir, "reports", args.input_dir),  
    )

if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    main()