# metrics/info_theory.py
from collections import defaultdict
from math import log2
from typing import Dict, Hashable, Tuple

def entropy_from_counts(
    counts: Dict[Hashable, int]
) -> Tuple[Dict[Hashable, float], float]:
    """
    Calculate entropy from counts.

    :param counts: dictionary {value: count}
    :return: (contributions of individual values, total entropy)
    """
    total = sum(counts.values()) # number of all frames with the field
    if total == 0:
        return {k: 0.0 for k in counts}, 0.0

    value_entropy = {}
    entropy = 0.0

    for val, c in counts.items():
        p = c / total
        if p > 0:
            h = -p * log2(p)
        else:
            h = 0.0
        value_entropy[val] = h
        entropy += h

    return value_entropy, entropy

def conditional_entropy(
    counts: Dict[Hashable, Dict[Hashable, int]]
):
    """
        H(X|Y) = -SUM(p(x,y)*log2(p(x|y)))
        p(x,y) = n_xy/N
        p(x|y) = n_xy/n_y

        n_xy - number of observation where X = x and Y = y
        n_y - number of observation where Y = y
        N - total number of observations
    """
    """
        input (X|Y): {LABEL: {value: count}}}
        input (Y|X): {value: {LABEL: count}}}
    """
    N = sum(sum(inner.values()) for inner in counts.values())
    if N == 0:
        return 0.0

    H = 0.0
    H_y = {}

    for y, values in counts.items():
        n_y = sum(values.values())
        if n_y == 0:
            continue

        for x, n_xy in values.items():
            if n_xy == 0:
                continue

            p_joint = n_xy / N      # p(x,y)
            p_cond = n_xy / n_y     # p(x|y)

            H -= p_joint * log2(p_cond)
            
        # H_y[y] = p_y * H - TO DO 

    return H

def mutual_information(
    counts: Dict[Hashable, Dict[Hashable, int]]
):
    """
        I(X;Y) = SUM(p(x,y)*log2(p(x,y)/p(x)p(y)))
        p(x,y) = n_xy/N
        n_xy - number of observation where X = x and Y = y
        n_y - number of observation where Y = y
        n_x - number of observation where X = x
    """

    N = sum(sum(inner.values()) for inner in counts.values())
    if N == 0:
        return 0.0
    
     # marginesy n_y i n_x
    n_y: Dict[Hashable, int] = {}
    n_x: Dict[Hashable, int] = defaultdict(int)

    for y, row in counts.items():
        total_y = sum(row.values())
        n_y[y] = total_y
        for x, n_xy in row.items():
            n_x[x] += n_xy

    I = 0.0

    for y, row in counts.items():
        for x, n_xy in row.items():
            if n_xy == 0:
                continue

            p_xy = n_xy / N
            p_x = n_x[x] / N
            p_y = n_y[y] / N

            denom = p_x * p_y
            if denom <= 0.0:
                continue

            I += p_xy * log2(p_xy / denom)

    return I

def normalized_mutual_information(
    counts: Dict[Hashable, Dict[Hashable, int]],
    H_x: float,
    H_y: float
):
    """
        NMI(X;Y) = I(X;Y) / max(I(X;Y)) -> max(I(X;Y)) = min(H(X), H(Y))
    """
    I = mutual_information(counts)

    if H_x == 0.0 or H_y == 0.0:
        return 0.0

    NMI = I / min(H_x, H_y)
    return NMI