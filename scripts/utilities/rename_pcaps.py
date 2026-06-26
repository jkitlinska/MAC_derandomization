#!/usr/bin/env python3
from pathlib import Path
import re
import sys

# Usage:
#   python rename_pcaps.py           -> change name.pcapX to X_name.pcap (X=0–417)
#   python rename_pcaps.py --dry-run -> preview changes without renaming files

DRY_RUN = "--dry-run" in sys.argv

pattern = re.compile(r'^(?P<base>.+\.pcap)(?P<idx>\d{1,3})$')  # np. "name.pcap0", "test_name.pcap123"

def main():
    cwd = Path(".")
    matches = []
    for p in cwd.iterdir():
        if not p.is_file():
            continue
        m = pattern.match(p.name)
        if not m:
            continue

        idx = int(m.group("idx"))
        if 0 <= idx <= 417:
            base = m.group("base")  # np. "name.pcap"
            new_idx = idx + 1
            new_name = f"{new_idx}_{base}"  # np. "1_name.pcap"
            target = p.with_name(new_name)

            matches.append((p, target))

    if not matches:
        print("No files found in the format name.pcapX (X=0–417).")
        return

    # Checking for collisions (existing files with the same target names)
    collisions = [t for _, t in matches if t.exists()]
    if collisions:
        print("ERROR: Files with the same target names already exist (no changes made):")
        for t in collisions:
            print("  -", t.name)
        print("Remove or rename conflicting files before running this script.")
        return

    # Performing (or previewing) the changes
    for src, dst in matches:
        if DRY_RUN:
            print(f"[DRY-RUN] {src.name}  ->  {dst.name}")
        else:
            src.rename(dst)
            print(f"Changed: {src.name}  ->  {dst.name}")

    if DRY_RUN:
        print("\nDry-run preview: no changes were made.")

if __name__ == "__main__":
    main()
