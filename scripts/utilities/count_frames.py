#!/usr/bin/env python3
import os
import sys
import json
import argparse
import glob

import pyshark


def count_frames_in_json(path):
    """
    counting frames in JSON files.
    Structure: list of devices, each has PROBE_REQs, and there lists of TIME.
    Number of frames = sum of lengths of TIME.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    total = 0
    # zakładamy: data to lista obiektów z polami MAC, LABEL, PROBE_REQs
    for dev in data:
        for burst in dev.get("PROBE_REQs", []):
            times = burst.get("TIME", [])
            total += len(times)
    return total


def count_frames_in_pcap(path, probe_only=False):
    """
    Counting frames in PCAP files.
    - if probe_only == False -> all frames (all packets)
    - if probe_only == True  -> only Probe Request (wlan.fc.type_subtype == 4)
    """
    if probe_only:
        display_filter = "wlan.fc.type_subtype == 4"
    else:
        display_filter = None

    total = 0
    cap = pyshark.FileCapture(
        path,
        display_filter=display_filter,
        keep_packets=False
    )

    try:
        for _ in cap:
            total += 1
    finally:
        cap.close()

    return total


def iter_input_files(inputs):
    """
    Takes a list of paths (files or directories), returns all matching .json, .pcap, .pcapng files (recursively for directories).
    """
    exts = {".json", ".pcap", ".pcapng"}

    for inp in inputs:
        if os.path.isdir(inp):
            # rekurencyjny glob
            for root, dirs, files in os.walk(inp):
                for fname in files:
                    _, ext = os.path.splitext(fname.lower())
                    if ext in exts:
                        yield os.path.join(root, fname)
        else:
            # pojedynczy plik, ewentualnie wildcardy
            if any(ch in inp for ch in ["*", "?", "["]):
                for path in glob.glob(inp):
                    if os.path.isfile(path):
                        _, ext = os.path.splitext(path.lower())
                        if ext in exts:
                            yield path
            else:
                if os.path.isfile(inp):
                    _, ext = os.path.splitext(inp.lower())
                    if ext in exts:
                        yield inp


def main():
    parser = argparse.ArgumentParser(
        description="Calculate and count frames in JSON (Probe Request) and PCAP files."
    )
    parser.add_argument(
        "--path",
        help="Files or catalogs (supported extensions: .json, .pcap, .pcapng)."
    )
    parser.add_argument(
        "--probe-only",
        action="store_true",
        help="For PCAP: calculate only Probe Requests (wlan.fc.type_subtype == 4)"
    )

    args = parser.parse_args()

    total_overall = 0
    any_file = False

    paths = os.path.normpath(os.path.join(os.path.dirname(__file__),"..", "..",  "dataset", args.path))

    for path in iter_input_files([paths]):
        any_file = True
        _, ext = os.path.splitext(path.lower())

        if ext == ".json":
            count = count_frames_in_json(path)
            print(f"[JSON ] {path}: {count} frames (Probe Requests)")
        elif ext in {".pcap", ".pcapng"}:
            count = count_frames_in_pcap(path, probe_only=args.probe_only)
            if args.probe_only:
                print(f"[PCAP ] {path}: {count} frames Probe Request")
            else:
                print(f"[PCAP ] {path}: {count} frames (all)")
        else:
            continue

        total_overall += count

    if not any_file:
        print("No files of type .json / .pcap / .pcapng found in the specified paths.", file=sys.stderr)
        sys.exit(1)

    print("-" * 60)
    print(f"Sum of frames in all files: {total_overall}")


if __name__ == "__main__":
    main()
