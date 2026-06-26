
def bit_dist(value1, value2, weight, length):
    '''
    Calculate bit distance from two values. Returned hamming distance is scaled by weight and length.
    '''
    xor = value1 ^ value2
    num_of_different_bits = bin(xor).count('1')
    return (num_of_different_bits/float(length)) * weight


def dist_data_rates(rates1, rates2, weight):
    '''
    Calculate distance between two supported data rates lists.
    The distance is calculated as length of non-overlapping rates list scaled by weight.
    '''
    set1 = set(rates1)
    set2 = set(rates2)
    
    intersection = set1.intersection(set2)
    union = set1.union(set2)
    
    if not union:
        return 0.0  # If both sets are empty, distance is zero.
    
    num_of_non_overlapping = len(union) - len(intersection)
    distance = num_of_non_overlapping * weight
    
    return distance

    
def conditional_bit_dist(value1, value2, weight, length, penalty=0):
    if len(value1) == len(value2):
        return bit_dist(value1, value2, weight, length)
    else:
        return penalty


def dist_vendor_spec(dict1, dict2, weight1, weight2, weight3):
    same_vendors = set(dict1.keys()).intersection(set(dict2.keys()))
    diff_vendors = set(dict1.keys()).symmetric_difference(set(dict2.keys()))
    dist = 0
    for vendor in same_vendors:
        dtypes1 = set(dict1[vendor].keys())
        dtypes2 = set(dict2[vendor].keys())
        same_dtypes = dtypes1.intersection(dtypes2)
        for dtype in same_dtypes:
            value1 = int(dict1[vendor][dtype], 16) # convert hex string to int
            value2 = int(dict2[vendor][dtype], 16)
            value1_bit_value = int(bin(value1)[2:],16)  # remove '0b' prefix and convert to bit value
            value2_bit_value = int(bin(value2)[2:],16)
            length = (len(dict1[vendor][dtype]) - 2) * 4  # -2 for '0x', *4 for bits
            dist += bit_dist(value1_bit_value, value2_bit_value, weight2, length)
        dist += len(same_dtypes) * weight3
    dist += (len(diff_vendors) - len(same_vendors)) * weight1

    # penalty if 0?
    
    return dist
    
    
def dist_ext_tag(dict1, dict2, weight1, weight2, weight3):
    same_tags = set(dict1.keys()).intersection(set(dict2.keys()))
    diff_tags = set(dict1.keys()).symmetric_difference(set(dict2.keys()))
    dist = 0
    for tag in same_tags:
        value1 = int(dict1[tag], 16) # convert hex string to int
        value2 = int(dict2[tag], 16)
        value1_bit_value = int(bin(value1)[2:],16)  # remove '0b' prefix and convert to bit value
        value2_bit_value = int(bin(value2)[2:],16)
        length = (len(dict1[tag]) - 2) * 4  # -2 for '0x', *4 for bits
        dist += bit_dist(value1_bit_value, value2_bit_value, weight2, length)
    dist += len(diff_tags) * weight1
    dist -= len(same_tags) * weight3
    return dist


def dist_rssi_time(rssi1, time1, rssi2, time2, weight1, weight2, weight3, weight4):
    min = float("inf")
    for i in range(0, len(rssi1)):
        for j in range(0, len(rssi2)):
            if abs(time1[i] - time2[j]) > weight4:
                time_dist = 1*weight2 + weight3
            else:
                time_dist = -1*weight2 + weight3
            temp = weight1 ** (abs(rssi1[i] - rssi2[j])) + time_dist     
            if temp < min:
                min = temp
    return min


def dist_ssid(ssid1, ssid2, weight):
    same_vendors = set(ssid1.keys()).intersection(set(ssid2.keys()))
    return len(same_vendors) * weight

    
def dist_IE_list_old(ie_list1, ie_list2, weight):
    same_ies = set(ie_list1).intersection(set(ie_list2))
    print("same_ies:", same_ies)
    diff_ies = set(ie_list1).symmetric_difference(set(ie_list2))
    print("diff_ies:", diff_ies)
    all_ies = set(ie_list1).union(set(ie_list2))
    print("all_ies:", all_ies)
    # Avoid division by zero
    if len(same_ies) == 0:
        return len(diff_ies) * weight

    return (len(diff_ies)/len(same_ies))*weight


# New multiset- and order-aware implementation (replaces previous behavior)
def dist_IE_list(ie_list1, ie_list2, weight):
    """Distance between two IE lists that accounts for duplicates and order.

    We use a multiset (counts) comparison to account for duplicates and the
    Longest Common Subsequence (LCS) length to capture ordering differences.

    Distance = (multiset_diff_count + order_diff) * weight
      - multiset_diff_count: number of elements not matched by counts
      - order_diff: max(len1, len2) - lcs_len (how many positions differ)

    Returns 0.0 when both lists are empty.
    """
    from collections import Counter

    # Quick return for both empty
    if not ie_list1 and not ie_list2:
        return 0.0

    c1 = Counter(ie_list1)
    c2 = Counter(ie_list2)

    # Multiset intersection count (counts duplicates)
    common_elems = set(c1.keys()).intersection(c2.keys())
    same_multiset_count = sum(min(c1[k], c2[k]) for k in common_elems)

    # Elements not matched by multiset counts
    diff_count = len(ie_list1) + len(ie_list2) - 2 * same_multiset_count

    # LCS length to capture ordering (works with duplicates)
    def lcs_length(a, b):
        n, m = len(a), len(b)
        if n == 0 or m == 0:
            return 0
        # Use a small DP table; optimize memory to two rows
        prev = [0] * (m + 1)
        for i in range(1, n + 1):
            cur = [0] * (m + 1)
            ai = a[i-1]
            for j in range(1, m + 1):
                if ai == b[j-1]:
                    cur[j] = prev[j-1] + 1
                else:
                    cur[j] = max(prev[j], cur[j-1])
            prev = cur
        return prev[m]

    lcs_len = lcs_length(ie_list1, ie_list2)
    order_diff = max(len(ie_list1), len(ie_list2)) - lcs_len

    # Combine differences: unmatched items + ordering penalties
    distance = (diff_count + order_diff) * weight
    return float(distance)
