# metrics/distributions.py
from collections import Counter
from typing import Dict, Hashable, Iterable


def distribution_from_counts(
    counts: Dict[Hashable, int],
    normalize: bool = False,
) -> Dict[Hashable, float]:
    """
    A general mathematical function that calculates the distribution of values.

    :param counts: dictionary {value: frequency}
    :param normalize: if True -> returns P(x) (sum = 1),
                      if False -> returns raw frequencies
    :return: {value: frequency or probability}
    """
    total = sum(counts.values())

    if not normalize:
        return {k: v for k, v in counts.items()}

    if total == 0:
        return {k: 0.0 for k in counts}

    return {k: v / total for k, v in counts.items()}


def distribution_from_values(
    values: Iterable[Hashable],
    normalize: bool = False,
) -> Dict[Hashable, float]:
    """
    A wrapper: calculates a Counter from values
    and passes it to distribution_from_counts.
    """
    c = Counter(values)
    return distribution_from_counts(dict(c), normalize=normalize)
