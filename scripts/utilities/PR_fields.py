import glob
import os
import json
import pyshark
import argparse
import csv
from collections import OrderedDict
# import pandas as pd

OUTPUT_CSV = "outputs/extracted_fields.csv"
INPUT_DIR = "dataset"

# JSON
def load_json():
    print("Loading JSON files...")
    json_files = glob.glob(os.path.join("dataset", "**", "*.json"), recursive=True)
    data = []
    for file_path in json_files:
        with open(file_path, "r") as f:
            try:
                file_data = json.load(f)
                if isinstance(file_data, list):
                    data.extend(file_data)
                else:
                    data.append(file_data)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
    return data

# EXTRACT PROBE REQUEST FROM JSON
def extract_probe_requests(json_data):
    probe_requests = []
    if isinstance(json_data, dict):
        for k,v in json_data.items():
            if k == "PROBE_REQs":
                probe_requests.extend(v)
    elif isinstance(json_data, list):
        for item in json_data:
            if isinstance(item, dict) and "PROBE_REQs" in item:
                probe_requests.extend(item["PROBE_REQs"])
    return probe_requests

# PCAP
def load_pcap():
    print("Loading PCAP files...")
    pcap_files = glob.glob(os.path.join("dataset", "**", "*.pcap"), recursive=True)
    devices = []

    for file_path in pcap_files:
        print(f"Processing file: {file_path}")
        try:
            capture = pyshark.FileCapture(file_path, use_json=True, include_raw=True)
            # for pkt in capture:
            #     devices.append(pkt)
            capture.close()
        except Exception as e:
            print(f"Error loading {file_path}: {e}")

    return capture

# FIELDS FROM JSON
def get_keys(obj, parent_key=""):
    keys = []
    if isinstance(obj, dict): # checking if the object is a dictionary
        for k, v in obj.items():
            full_key = f"{parent_key}.{k}" if parent_key else k
            if full_key not in keys:
                keys.append(full_key)
                keys.extend(get_keys(v, full_key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            keys.extend(get_keys(item, parent_key))
    keys = list(OrderedDict.fromkeys(keys))  # Remove duplicates while preserving order
    return keys


# FIELDS FROM PCAP
def get_pcap_fields(pcap_data):
    fields = set()
    for packet in pcap_data:
        for layer in packet.layers:
            for field in layer.field_names:
                fields.add(f"{layer.layer_name}.{field}")
    return list(fields)


# FIELDS TO CSV
def save_to_csv(data, dataset_type):
    with open(OUTPUT_CSV, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([os.path.basename(dataset_type)])
        for item in data:
            writer.writerow([item])
    print ("Fields saved to CSV")

## main function
def main():
    parser = argparse.ArgumentParser(description="Extract fields from JSON and PCAP files")
    parser.add_argument('--dataset', type=str, default='JSON', help='Path to the dataset directory')
    args = parser.parse_args()

    if args.dataset == 'JSON':
        json_data = load_json()
        print("Loaded JSON file.")
        probe_requests = extract_probe_requests(json_data)
        print(f"Extracted {len(probe_requests)} probe requests.")
        keys = get_keys(probe_requests)
        print(f"Extracted {len(keys)} unique fields from probe requests.")
        save_to_csv(keys,"JSON dataset")
    elif args.dataset == 'PCAP':
        pcap_data = load_pcap()
        print("Loaded PCAP file. Number of packets:", len(pcap_data))
        pcap_fields = get_pcap_fields(pcap_data)
        print(f"Extracted {len(pcap_fields)} unique fields from PCAP.")
        # save_to_csv(pcap_fields,"PCAP dataset")
        print(pcap_fields)
    else:
        print("This dataset is not supported. Please choose 'JSON' or 'PCAP'.")

main()