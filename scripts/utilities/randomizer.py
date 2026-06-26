from scapy.all import PcapReader, PcapWriter, Dot11
try:
    from scapy.utils import PcapNgWriter
    HAS_PCAPNG = True
except Exception:
    HAS_PCAPNG = False

import argparse, os

def dev_prefix(dev_id: int) -> str:
    """
    Generates a unique 3B prefix for the device:
    02:HH:LL (02 = LAA unicast, HH:LL = dev_id mod 65536)
    """
    if dev_id < 1 or dev_id > 0xFFFF:
        # jeśli >65535 urządzeń, łatwo rozszerzyć na 24 bity
        dev_id = dev_id & 0xFFFF
    return f"02:{(dev_id>>8)&0xFF:02x}:{dev_id&0xFF:02x}"

def suffix_from(counter: int) -> str:
    """
    24-bitowy increasing suffix for the device frames.
    """
    if counter < 1 or counter > 0xFFFFFF:
        counter = counter & 0xFFFFFF
        if counter == 0:
            counter = 1
    return f"{(counter>>16)&0xFF:02x}:{(counter>>8)&0xFF:02x}:{counter&0xFF:02x}"

def writer_for(path_out):
    ext = os.path.splitext(path_out)[1].lower()
    if ext == ".pcapng" and HAS_PCAPNG:
        return PcapNgWriter(path_out, sync=True)
    return PcapWriter(path_out, sync=True)

def run(pcap_in, pcap_out, start_suffix):
    # maps: original_src -> device_id and frame counter
    device_id_map = {}      # str -> int   (next device ID)
    device_counters = {}    # int -> int   (suffix counter per device)
    next_dev_id = 1

    total = changed = 0

    with PcapReader(pcap_in) as pr, writer_for(pcap_out) as pw:
        for pkt in pr:
            total += 1
            if Dot11 in pkt:
                src = pkt[Dot11].addr2
                if src:
                    if src not in device_id_map:
                        device_id_map[src] = next_dev_id
                        device_counters[next_dev_id] = start_suffix
                        next_dev_id += 1
                    did = device_id_map[src]

                    # nowy mac
                    pref = dev_prefix(did)
                    suf = suffix_from(device_counters[did])
                    pkt[Dot11].addr2 = f"{pref}:{suf}"

                    device_counters[did] += 1
                    changed += 1

            pw.write(pkt)

    print(f"Saved: {pcap_out}")
    print(f"Frames total: {total}")
    print(f"Modified 802.11 addr2: {changed}")
    print(f"Devices (unique source MACs): {len(device_id_map)}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Per-device: a different prefix (3B), and the suffix (3B) consists of ascending numbers for each sample of this device."
    )
    ap.add_argument("pcap_in", help="input .pcap / .pcapng (Radiotap/802.11)")
    ap.add_argument("pcap_out", help="output .pcap / .pcapng")
    ap.add_argument("--start-suffix", type=int, default=1, help="start value for the suffix counter for each device (default: 1)")
    args = ap.parse_args()
    run(args.pcap_in, args.pcap_out, args.start_suffix)
