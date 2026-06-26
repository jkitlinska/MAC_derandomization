# metrics/cardinality.py
from collections import Counter
from typing import Iterable, Hashable, Dict, Set, Tuple


def cardinality_from_values(
    values: Iterable[Hashable],
) -> Tuple[int, Set[Hashable]]:
    """
    How many distinct values are there in the `values` sequence?

    Returns (number_of_distinct_values, set_of_values).
    """
    unique_values: Set[Hashable] = set(values)
    return len(unique_values), unique_values


def per_group_cardinality(
    groups: Dict[Hashable, Iterable[Hashable]],
) -> Dict[Hashable, int]:
    """
    Calculates the cardinality per group (e.g., per device).

    groups: key -> iterable(values)

    Returns: key -> number_of_distinct_values_in_that_group.
    """
    return {key: len(set(vals)) for key, vals in groups.items()}


def histogram_from_cardinality(
    per_group: Dict[Hashable, int],
) -> Counter:
    """
    From `key -> number_of_distinct_values` creates a histogram:
    n_distinct -> number_of_groups.
    """
    return Counter(per_group.values())
