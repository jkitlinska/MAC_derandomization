# data_loaders/load_pcap.py
import glob
import os
import re
import pyshark
import multiprocessing as mp
from functools import partial
from typing import Optional
from src.metrics.common import count_frames_in_devices


# ======================= MERGING HELPERS =======================

def _merge_pr_list(pr_list, new_pr):
    """
    Jeśli istnieje PROBE_REQ z takim samym DATA,
    dopisujemy TIME i RSSI; inaczej dodajemy nowy wpis.
    """
    found = False
    for pr in pr_list:
        if pr["DATA"] == new_pr["DATA"]:
            pr["TIME"].extend(new_pr["TIME"])
            pr["RSSI"].extend(new_pr["RSSI"])
            found = True
            break
    if not found:
        pr_list.append(new_pr)


def _merge_device_into(target_by_id, src_dev, labeled: bool):
    """
    Scala urządzenie src_dev do target_by_id.
    Kluczem jest zawsze MAC; opcjonalnie ustawiany jest LABEL.
    """
    device_id = src_dev.get("MAC")
    if device_id is None:
        return

    dev = target_by_id.get(device_id)
    if dev is None:
        dev = {
            "MAC": device_id,
            "PROBE_REQs": []
        }
        if labeled and src_dev.get("LABEL") is not None:
            dev["LABEL"] = src_dev["LABEL"]
        target_by_id[device_id] = dev
    else:
        if labeled and dev.get("LABEL") is None and src_dev.get("LABEL") is not None:
            dev["LABEL"] = src_dev["LABEL"]

    # PROBE_REQs (scalanie po identycznym DATA)
    for pr in src_dev.get("PROBE_REQs", []) or []:
        _merge_pr_list(
            dev["PROBE_REQs"],
            {
                "TIME": list(pr.get("TIME", [])),
                "RSSI": list(pr.get("RSSI", [])),
                "DATA": pr.get("DATA", {})
            }
        )


# ======================= PARSING HELPERS =======================

def _to_int_safe(tok):
    """Próba zamiany na int z różnych form ('42', 42, '0x2A', ' -40 ', ' -43.0 ', itd.)."""
    if tok is None:
        return None
    if isinstance(tok, int):
        return tok
    s = str(tok).strip()
    try:
        return int(s)
    except Exception:
        pass
    try:
        return int(float(s))
    except Exception:
        pass
    m = re.search(r'0x([0-9A-Fa-f]+)', s)
    if m:
        try:
            return int(m.group(1), 16)
        except Exception:
            pass
    m = re.search(r'x?([0-9A-Fa-f]{2,})$', s)
    if m:
        try:
            return int(m.group(1), 16)
        except Exception:
            pass
    m = re.search(r'([+-]?\d+)$', s)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            pass
    return None


def _safe_raw_at(raws, i, cut_chars=0):
    """Zwraca raws[i][0] jako string (ucięty o cut_chars), albo None jeśli brak/format nie ten."""
    try:
        if not isinstance(raws, list) or i < 0 or i >= len(raws):
            return None
        row = raws[i]
        raw = row[0] if isinstance(row, list) else row
        if not isinstance(raw, str):
            return None
        if cut_chars:
            if len(raw) < cut_chars:
                return None
            raw = raw[cut_chars:]
        return raw
    except Exception:
        return None


# ======================= SINGLE PCAP FILE =======================

def process_pcap_file(file_path: str, labeled: bool, label_from: str):
    """
    Parsuje pojedynczy plik PCAP i zwraca devices_by_id (lokalne),
    strukturalnie zgodne z JSONami:
      [
        {
          "MAC": "...",
          "LABEL": "...",   # tylko dla labeled
          "PROBE_REQs": [ ... ]
        },
        ...
      ]
    """
    devices_by_id = {}

    folder_label = os.path.basename(os.path.dirname(file_path))
    file_label = os.path.splitext(os.path.basename(file_path))[0]

    print(f"[worker] Przetwarzanie pliku: {file_path}")

    try:
        capture = pyshark.FileCapture(
            file_path,
            use_json=True,
            include_raw=True,
            keep_packets=False,
            # uncomment the following line to filter only probe requests (type/subtype 4) - recommended for PCAPs with different frame types
            # display_filter="wlan.fc.type_subtype == 4",
        )

        for pkt in capture:
            try:
                if not hasattr(pkt, "wlan") or not hasattr(pkt, "wlan_radio"):
                    continue

                pr_data = {}
                ssid = ""

                # source MAC address (SA)
                try:
                    mac = pkt.wlan.sa
                except Exception:
                    continue

                # czas jako string (tak jak w JSONach)
                sniff_time = pkt.sniff_timestamp

                # RSSI jako string (tak jak w JSONach)
                try:
                    rssi_val = int(pkt.wlan_radio.signal_dbm)
                except Exception:
                    rssi_val = -200  # fallback
                rssi = str(rssi_val)

                # device_id is MAC address (SA) - unique device identifier
                device_id = mac

                # label for labeled dataset
                label_value = None
                if labeled:
                    label_value = file_label if label_from == "file" else folder_label

                # tagged fields
                try:
                    tagged = pkt[7]._all_fields.get("wlan.tagged.all", {})
                except Exception:
                    tagged = {}

                tag_list = tagged.get("wlan.tag", [])
                if not isinstance(tag_list, list):
                    tag_list = [tag_list]
                tag_raws = tagged.get("wlan.tag_raw", [])

                for i, tag in enumerate(tag_list):
                    try:
                        tag_num = tag["wlan.tag.number"]
                        pr_data["TAG_LIST"] = pr_data.get("TAG_LIST", []) + [tag_num]
                    except Exception:
                        continue

                    if tag_num == "0":
                        ssid = tag.get("wlan.ssid", "")
                    elif tag_num == "1":
                        supp = tag.get("wlan.supported_rates", [])
                        if not isinstance(supp, list):
                            supp = [supp]
                        supp_vals = []
                        for x in supp:
                            v = _to_int_safe(x)
                            if v is not None:
                                supp_vals.append(str(v))
                        pr_data.setdefault("DATA_RTS", {})["SUPP"] = supp_vals

                    elif tag_num == "50":
                        ext = tag.get("wlan.extended_supported_rates", [])
                        if not isinstance(ext, list):
                            ext = [ext]
                        ext_vals = []
                        for x in ext:
                            v = _to_int_safe(x)
                            if v is not None:
                                ext_vals.append(str(v))
                        pr_data.setdefault("DATA_RTS", {})["EXT"] = ext_vals

                    elif tag_num == "45":
                        raw_hex = _safe_raw_at(tag_raws, i, cut_chars=4)
                        if raw_hex is not None:
                            pr_data["HT_CAP"] = "0x" + raw_hex
                            ht_bytes = bytes.fromhex(raw_hex)

                            # CHECK IT
                            pr_data["HT_CAP_INFO"]    = ht_bytes[0:2].hex()   # 2 B
                            pr_data["HT_AMPDU_PARMS"] = ht_bytes[2:3].hex()   # 1 B
                            pr_data["HT_MCS_SET"]     = ht_bytes[3:19].hex()  # 16 B (3..18)
                            pr_data["HT_EXT_CAP"]     = ht_bytes[19:21].hex() # 2 B (19..20)
                            pr_data["HT_Tx"]          = ht_bytes[21:25].hex() # 4 B (21..24)
                            pr_data["HT_ANTENNA"]     = ht_bytes[25:26].hex() # 1 B (25)

                    elif tag_num == "127":
                        raw_hex = _safe_raw_at(tag_raws, i, cut_chars=4)
                        if raw_hex is not None:
                            pr_data["EXT_CAP"] = "0x" + raw_hex

                    elif tag_num == "191":
                        raw_hex = _safe_raw_at(tag_raws, i, cut_chars=4)
                        if raw_hex is not None:
                            pr_data["VHT_CAP"] = "0x" + raw_hex

                    elif tag_num == "107":
                        raw_hex = _safe_raw_at(tag_raws, i, cut_chars=4)
                        if raw_hex is not None:
                            pr_data["INTWORK"] = "0x" + raw_hex

                    elif tag_num == "221":
                        vendor_spec = pr_data.setdefault("VENDOR_SPEC", {})

                        length = _to_int_safe(tag.get("wlan.tag.length"))
                        raw_data = _safe_raw_at(tag_raws, i, cut_chars=0)
                        if length is None or raw_data is None:
                            continue

                        oui = tag.get("wlan.tag.vendor.oui")
                        data_id = tag.get("wlan.tag.vendor.oui.type")

                        # normalie to raw hex
                        hex_raw = str(raw_data).lower().replace("0x", "").replace(":", "").replace(" ", "")

                        # detect OUI and TYPE from raw if not present in tag
                        # Vendor IE: dd LL OUI(3B) TYPE(1B) PAYLOAD(...)
                        offset = 0
                        if len(hex_raw) >= 4 and hex_raw[:2] == "dd":
                            offset = 4  # pomiń dd + length (2 bajty -> 4 znaki hex)

                        # fallback
                        if (not oui or not data_id) and len(hex_raw) >= offset + 8:
                            oui_hex = hex_raw[offset:offset+6]        # 3 bajty
                            type_hex = hex_raw[offset+6:offset+8]     # 1 bajt
                            if not oui:
                                oui = f"{oui_hex[0:2]}:{oui_hex[2:4]}:{oui_hex[4:6]}"
                            if not data_id:
                                data_id = str(int(type_hex, 16))

                        oui = oui or "UNKNOWN_OUI"
                        data_id = data_id or "UNKNOWN_TYPE"

                        payload_bytes = max(0, length - 4)
                        payload_hex_len = payload_bytes * 2

                        payload = hex_raw[-payload_hex_len:] if payload_hex_len else ""
                        data = "0x" + payload

                        vendor_spec.setdefault(oui, {})[data_id] = data

                # EXT_TAG
                if "wlan.ext_tag" in tagged:
                    ext_tags = tagged["wlan.ext_tag"]
                    ext_tag_raws = tagged.get("wlan.ext_tag_raw", [])
                    pr_data["EXT_TAG"] = {}
                    if isinstance(ext_tags, list):
                        for i, ext_tag in enumerate(ext_tags):
                            try:
                                tag_num = ext_tag["wlan.ext_tag.number"]
                            except Exception:
                                continue
                            raw_data = _safe_raw_at(ext_tag_raws, i, cut_chars=2)
                            if raw_data is None:
                                continue
                            pr_data["EXT_TAG"][tag_num] = "0x" + raw_data
                    else:
                        try:
                            tag_num = ext_tags["wlan.ext_tag.number"]
                            raw_data = _safe_raw_at(ext_tag_raws, 0, cut_chars=2)
                            if raw_data is not None:
                                pr_data["EXT_TAG"] = {tag_num: "0x" + raw_data}
                        except Exception:
                            pass

                dev = devices_by_id.get(device_id)
                if dev is None:
                    dev = {
                        "MAC": mac,
                        "PROBE_REQs": [
                            {"TIME": [sniff_time], "RSSI": [rssi], "DATA": pr_data}
                        ],
                    }
                    if labeled and label_value is not None:
                        dev["LABEL"] = label_value
                    devices_by_id[device_id] = dev
                else:
                    if labeled and dev.get("LABEL") is None and label_value is not None:
                        dev["LABEL"] = label_value

                    _merge_pr_list(
                        dev["PROBE_REQs"],
                        {"TIME": [sniff_time], "RSSI": [rssi], "DATA": pr_data},
                    )

            except Exception as e:
                print(f"[worker] Błąd pakietu w {file_path}: {e}")

        capture.close()

    except Exception as e:
        print(f"[worker] Błąd wczytywania {file_path}: {e}")

    return devices_by_id


# ======================= PUBLIC API =======================

def load_pcap(
    input_dir: str,
    labeled: bool = False,
    label_from: str = "folder",   # 'folder' lub 'file'
    workers: Optional[int] = None
):
    """
    Reads all PCAP files from the specified directory (recursively)
    and returns a list of devices in a JSON-compatible format:
      [
        {
          “MAC”: “...”,
          “LABEL”: “...”,   # only for labeled files
          “PROBE_REQs”: [ ... ]
        },
        ...
      ]
    """
    print("Loading PCAP files from:", input_dir)
    pcap_files = glob.glob(os.path.join(input_dir, "**", "*.pcap"), recursive=True)
    if not pcap_files:
        print("No PCAP files found.")
        return []

    # number of workers: if specified, use that; otherwise, use min(cpu_count-1, 6, len(pcap_files))
    if workers is not None:
        max_procs = max(1, min(int(workers), len(pcap_files)))
    else:
        max_procs = min(max(1, (os.cpu_count() or 2) - 1), 6, len(pcap_files))

    print(f"Starting parallel processing: {max_procs} process(es)")
    devices_by_id = {}

    with mp.get_context("spawn").Pool(processes=max_procs) as pool:
        worker = partial(process_pcap_file, labeled=labeled, label_from=label_from)
        for local_map in pool.imap_unordered(worker, pcap_files, chunksize=1):
            if not local_map:
                continue
            for dev_id, src_dev in local_map.items():
                _merge_device_into(devices_by_id, src_dev, labeled)

    # convert devices_by_id to a list of devices
    devices = list(devices_by_id.values())

    print("Loaded PCAP file(s). Number of frames:", count_frames_in_devices(devices))
    return devices
