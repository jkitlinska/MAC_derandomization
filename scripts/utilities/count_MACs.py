#!/usr/bin/env python3
import os
import argparse
import multiprocessing as mp
import re
from pathlib import Path
from typing import Set, List, Tuple, Optional

import pyshark


def list_pcap_files(input_path: str) -> List[str]:
    """
    Returns a list of all PCAP/PCAPNG/CAP files in the directory (recursively)
    or a single file if the path points to a file.
    """
    input_path = os.path.abspath(input_path)

    if os.path.isfile(input_path):
        return [input_path]

    pcap_files = []
    for root, _, files in os.walk(input_path):
        for fname in files:
            if fname.lower().endswith((".pcap", ".pcapng", ".cap")):
                pcap_files.append(os.path.join(root, fname))

    return sorted(pcap_files)


def extract_device_name(path: str) -> Optional[str]:
    """
    Extracts folder name matching pattern: data_devX_dataset
    where X is a single letter.
    """
    for part in Path(path).parts:
        if re.fullmatch(r"data_dev[A-Za-z]_dataset", part):
            return part
    return None


def process_single_pcap(pcap_path: str) -> Tuple[Set[str], Optional[str], int]:
    """
    Processes a single PCAP file:
    - filters Probe Request frames (wlan.fc.type_subtype == 4)
    - extracts source MAC (wlan.sa or wlan.ta)
    - returns:
        * set of unique MACs from this file
        * device name extracted from path
        * number of Probe Request packets in this file
    """
    macs: Set[str] = set()
    packet_count = 0
    device = extract_device_name(pcap_path)
    capture = None

    try:
        capture = pyshark.FileCapture(
            pcap_path,
            display_filter="wlan.fc.type_subtype == 4",
            keep_packets=False,
        )

        for pkt in capture:
            try:
                wlan = pkt.wlan
            except AttributeError:
                continue

            mac = None
            if hasattr(wlan, "sa"):
                mac = wlan.sa
            elif hasattr(wlan, "ta"):
                mac = wlan.ta

            if mac:
                macs.add(mac.lower())

            packet_count += 1

    except Exception as e:
        print(f"[WARN] Error processing file {pcap_path}: {e}")

    finally:
        if capture is not None:
            capture.close()

    return macs, device, packet_count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Count unique MACs sending Probe Requests in PCAP/PCAPNG files, "
            "globally and per device folder."
        )
    )
    parser.add_argument(
        "input_path",
        help="Directory with PCAPs (recursively) or a single PCAP/PCAPNG file.",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=mp.cpu_count(),
        help="Number of parallel processes (default: number of CPU cores)",
    )
    parser.add_argument(
        "--show-macs",
        action="store_true",
        help="Print all unique MACs at the end",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if os.path.isabs(args.input_path):
        path = args.input_path
    else:
        path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "dataset", args.input_path)
        )

    pcap_files = list_pcap_files(path)
    if not pcap_files:
        print(f"No PCAP/PCAPNG files found in: {path}")
        return

    total_files = len(pcap_files)

    print(f"Found {total_files} PCAP/PCAPNG files.")
    print(f"Using {args.workers} parallel processes.\n")

    all_macs: Set[str] = set()
    dev_to_packet_count = {}
    dev_to_macs = {}

    with mp.Pool(processes=args.workers) as pool:
        for i, (mac_set, device, packet_count) in enumerate(
            pool.imap_unordered(process_single_pcap, pcap_files),
            start=1,
        ):
            all_macs.update(mac_set)

            if device:
                dev_to_packet_count[device] = (
                    dev_to_packet_count.get(device, 0) + packet_count
                )

                if device not in dev_to_macs:
                    dev_to_macs[device] = set()
                dev_to_macs[device].update(mac_set)

            if i % 10 == 0 or i == total_files:
                percent = i / total_files * 100
                print(
                    f"Processed {i}/{total_files} files ({percent:.1f}%)...",
                    flush=True,
                )

    print("\n======================================")
    print(f"Number of unique devices (global MACs): {len(all_macs)}")
    print("======================================\n")

    print("Per-device statistics:")
    for device in sorted(dev_to_packet_count.keys()):
        probe_requests = dev_to_packet_count.get(device, 0)
        unique_macs = len(dev_to_macs.get(device, set()))
        print(
            f"{device}: {probe_requests} Probe Requests, "
            f"{unique_macs} unique MACs"
        )

    if args.show_macs:
        print("\nAll unique MACs:")
        for mac in sorted(all_macs):
            print(mac)


if __name__ == "__main__":
    main()