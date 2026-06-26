def mac_anonymity_set_size(mac_to_fps):
    """
    Calculate the anonymity set size based on MAC addresses and their associated fingerprints.

    Args:
        mac_to_fps (dict): A dictionary mapping MAC addresses to a list of fingerprints.   
    """
    fp_to_macs = {}

    for mac, fps in mac_to_fps.items():
        # print(f"Processing MAC: {mac} with fingerprints: {fps}")
        for fp in fps:
            fp = str(fp)  # Convert list to string for consistent hashing
            if fp not in fp_to_macs:
                fp_to_macs[fp] = set()
            fp_to_macs[fp].add(mac)

    fp_size = {}

    for fp, macs in fp_to_macs.items():
        fp_size[fp] = len(macs)

    anonymity_set_sizes = {}

    for fp, X in fp_size.items():
        if X not in anonymity_set_sizes:
            anonymity_set_sizes[X] = 0
        anonymity_set_sizes[X] += X

    return anonymity_set_sizes

def device_anonymity_set_size(device_to_fps):
    """
    Calculate the anonymity set size based on MAC addresses and their associated fingerprints.

    Args:
        device_to_fps (dict): A dictionary mapping devices to a list of fingerprints.
    """
    fp_to_device = {}

    for device, fps in device_to_fps.items():
        for fp in fps:
            fp = str(fp)  # Convert list to string for consistent hashing
            if fp not in fp_to_device:
                fp_to_device[fp] = set()
            fp_to_device[fp].add(device)
    fp_size = {}

    for fp, devices in fp_to_device.items():
        fp_size[fp] = len(devices)

    anonymity_set_sizes = {}
    

    for fp, X in fp_size.items():
        if X not in anonymity_set_sizes:
            anonymity_set_sizes[X] = 0
        anonymity_set_sizes[X] += X

    return anonymity_set_sizes, fp_to_device

def fingerprint_sharing_distribution(device_to_fps):
    """
    Calculate the anonymity set size based on MAC addresses and their associated fingerprints.

    Args:
        device_to_fps (dict): A dictionary mapping devices to a list of fingerprints.
    """
    sharing_dist = {}
    fp_to_devices = {}

    for device, fps in device_to_fps.items():
        for fp in fps:
            fp = str(fp)  # Convert list to string for consistent hashing
            if fp not in fp_to_devices:
                fp_to_devices[fp] = set()
            fp_to_devices[fp].add(device)

    for fp, devices in fp_to_devices.items():
        X = len(devices)
        if X not in sharing_dist:
            sharing_dist[X] = 0

        sharing_dist[X] += 1


    return sharing_dist