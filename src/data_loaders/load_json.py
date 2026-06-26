# data_loaders/load_json.py
import glob
import os
import json

def load_json(input_dir):
    print("Loading JSON files...")

    json_files = glob.glob(os.path.join(input_dir, "**", "*.json"), recursive=True)
    print("Found files:", json_files)

    data = []
    for file_path in json_files:
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                file_data = json.load(f)
                if isinstance(file_data, list):
                    data.extend(file_data)
                else:
                    data.append(file_data)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
    return data
