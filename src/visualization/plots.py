# visualization/plots.py

import math
import os
from typing import Dict, List, Sequence, Mapping

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.ticker import MaxNLocator


_SINGLE_COLOR = "#c71585"
_GRID_COLOR = "#d9d9d9"

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Computer Modern Roman", "CMU Serif", "DejaVu Serif"],
    "mathtext.fontset": "cm",
    "axes.unicode_minus": False,

    "font.size": 10,
    "axes.labelsize": 11,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,

    "axes.linewidth": 0.8,
    "xtick.major.width": 0.8,
    "ytick.major.width": 0.8,
    "xtick.major.size": 3,
    "ytick.major.size": 3,
})


def _auto_bar_width(xs, factor=0.28, max_width=0.28):
    """
    It adjusts the width of the bars based on the spacing between the X-values.
    """
    if len(xs) <= 1:
        return max_width

    distances = [
        xs[i + 1] - xs[i]
        for i in range(len(xs) - 1)
        if xs[i + 1] > xs[i]
    ]

    if not distances:
        return max_width

    return min(min(distances) * factor, max_width)


def _set_all_integer_xticks(ax, xs, x_max=None):
    """
    Forces all subsequent integers onto the X-axis.
    If x_max is specified, the X-axis ends at that value.
    """
    if not xs and x_max is None:
        return

    if xs:
        min_x = int(min(xs))
        max_x = int(max(xs))
    else:
        min_x = 1
        max_x = int(x_max)

    if x_max is not None:
        max_x = int(x_max)

    ax.set_xticks(list(range(min_x, max_x + 1)))
    ax.set_xlim(min_x - 0.5, max_x + 0.5)


def _style_axis(ax):
    ax.set_axisbelow(True)

    ax.grid(
        True,
        which="major",
        axis="both",
        color=_GRID_COLOR,
        linewidth=0.8,
        alpha=0.9,
    )

    for spine in ax.spines.values():
        spine.set_linewidth(0.8)
        spine.set_color("black")

    ax.tick_params(
        axis="both",
        which="both",
        direction="out",
        top=True,
        right=False,
        width=0.8,
        length=3,
    )

    ax.yaxis.set_major_locator(MaxNLocator(integer=True))

    ax.margins(y=0)

_BASE_PALETTE = [
    "#c71585",  
    "#ff4fe3",
    "#ff99f7",
    "#d000ff",
    "#a200ff",
    "#7a2cff",
    "#b300ff",
]


def _ensure_dir(path: str) -> None:
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


def _get_palette(n: int) -> List[str]:
    if n <= len(_BASE_PALETTE):
        return _BASE_PALETTE[:n]
    # powielamy paletę jeśli trzeba więcej
    repeats = int(np.ceil(n / len(_BASE_PALETTE)))
    palette = (_BASE_PALETTE * repeats)[:n]
    return palette


def _get_pink_purple_cmap() -> LinearSegmentedColormap:
    colors = ["#ffe6fb", "#ff99f7", "#ff4fe3", "#c71585", "#b300ff", "#6a00ff"]
    return LinearSegmentedColormap.from_list("pink_purple", colors)


def _shorten_label(value: str, max_len: int = 16) -> str:
    """
    Shortens long hex values to a format like '0xef0903ff...810800'.
    Leaves short labels and 'OTHER' unchanged.
    """
    if value == "OTHER":
        return value
    if len(value) <= max_len:
        return value

    # np. 8 pierwszych i 4 ostatnie znaki
    prefix_len = 8
    suffix_len = 4
    if len(value) <= prefix_len + suffix_len + 3:
        return value

    return f"{value[:prefix_len]}...{value[-suffix_len:]}"


# ===========================================================
#  1. GLOBAL DISTRIBUTION OF VALUES FOR A SINGLE FIELD
# ===========================================================

def plot_global_distribution(
    field_name: str,
    value_to_count: Mapping[str, int],
    top_n: int = 15,
    use_probabilities: bool = True,
    output_path: str = "outputs/results/{field}_global_distribution.pdf",
    abbreviate_labels: bool = True,
    max_label_len: int = 16,
) -> None:
    """
    Plots a bar chart of the field's values (Top-N + ‘OTHER’).

    :param field_name: Field name (e.g., “HT_CAP”).
    :param value_to_count: dict/Mapping: value -> number of frames.
    :param top_n: How many of the most frequent values to show separately.
    :param use_probabilities: If True, normalizes to probabilities.
    :param output_path: Path to save the file (may contain {field}).
    :param abbreviate_labels: If True, shortens long hex labels.
    :param max_label_len: Target maximum label length (before shortening).
    """
    output_path = output_path.format(field=field_name)

    # sortujemy malejąco po liczbie wystąpień
    items = sorted(value_to_count.items(), key=lambda x: x[1], reverse=True)
    top_items = items[:top_n]
    other_items = items[top_n:]

    labels = [v for v, _ in top_items]
    counts = np.array([c for _, c in top_items], dtype=float)

    if other_items:
        labels.append("OTHER")
        counts = np.append(counts, sum(c for _, c in other_items))

    if use_probabilities:
        total = counts.sum()
        if total > 0:
            values = counts / total
        else:
            values = counts
        y_label = "Probability"
    else:
        values = counts
        y_label = "Count"

    x = np.arange(len(labels))

    # abbreviate labels if needed
    if abbreviate_labels:
        display_labels = [_shorten_label(v, max_label_len) for v in labels]
    else:
        display_labels = labels

    plt.figure(figsize=(10, 5))
    plt.bar(x, values, color=_SINGLE_COLOR)
    plt.xticks(x, display_labels, rotation=60, ha="right", fontsize=8)
    plt.ylabel(y_label)
    plt.xlabel("Value")
    plt.title(f"Global distribution for field {field_name}")
    plt.tight_layout()

    _ensure_dir(output_path)
    plt.savefig(output_path, format="pdf")
    plt.close()


# ===========================================================
#  2. K-SUMMARY FOR A SINGLE FIELD
# ===========================================================

def plot_k_summary(
    field_name: str,
    k_to_value_count: Mapping[int, int],
    output_path: str = "outputs/results/{field}_k_summary.pdf",
) -> None:
    """
    Plots a bar chart of the K-summary: how many values appear on exactly k devices.

    :param field_name: Field name.
    :param k_to_value_count: dict: k -> number of values with that k.
    :param output_path: Path to save the file (may contain {field}).
    """
    output_path = output_path.format(field=field_name)

    ks = sorted(k_to_value_count.keys())
    counts = [k_to_value_count[k] for k in ks]
    x = np.arange(len(ks))

    plt.figure(figsize=(6, 4))
    plt.bar(x, counts, color=_SINGLE_COLOR)
    plt.xticks(x, ks)
    plt.xlabel("k (number of devices with given value)")
    plt.ylabel("Number of values")
    plt.title(f"K-summary for field {field_name}")
    plt.tight_layout()

    _ensure_dir(output_path)
    plt.savefig(output_path, format="pdf")
    plt.close()


# ===========================================================
#  3. CARDINALITY PER DEVICE FOR A SINGLE FIELD
# ===========================================================

def plot_per_device_cardinality(
    field_name: str,
    cardinality_to_device_count: Mapping[int, int],
    output_path: str = "outputs/results/{field}_per_device_cardinality.pdf",
) -> None:
    """
    Histogram: how many devices have a given number of distinct values for the field.

    :param field_name: Field name.
    :param cardinality_to_device_count: dict: cardinality -> number of devices.
    :param output_path: Path to save the file (may contain {field}).
    """
    output_path = output_path.format(field=field_name)

    card = sorted(cardinality_to_device_count.keys())
    counts = [cardinality_to_device_count[c] for c in card]
    x = np.arange(len(card))

    plt.figure(figsize=(6, 4))
    plt.bar(x, counts, color=_SINGLE_COLOR)
    plt.xticks(x, card)
    plt.xlabel("Number of distinct values per device")
    plt.ylabel("Number of devices")
    plt.title(f"Per-device cardinality for field {field_name}")
    plt.tight_layout()

    _ensure_dir(output_path)
    plt.savefig(output_path, format="pdf")
    plt.close()


# ===========================================================
#  4. ENTROPIA AND MI
# ===========================================================

def plot_entropy_mi_per_field(
    field_name: str,
    entropy: float,
    mutual_info: float,
    cond_entropy_device: float | None = None,
    output_path: str = "outputs/results/{field}_entropy_mi.pdf",
) -> None:
    """
    Plots a bar chart for a single field, comparing:
      - H(field)
      - optionally H(field | device)
      - I(field; device)

    :param field_name: Field name (e.g., "HT_CAP").
    :param entropy: H(field).
    :param mutual_info: I(field; device).
    :param cond_entropy_device: (optionally) H(field | device).
    :param output_path: Path to the file (may contain {field}).
    """
    output_path = output_path.format(field=field_name)

    metrics = ["H(field)"]
    values = [entropy]

    if cond_entropy_device is not None:
        metrics.append("H(field | device)")
        values.append(cond_entropy_device)

    metrics.append("I(field; device)")
    values.append(mutual_info)

    x = np.arange(len(metrics))
    palette = _get_palette(len(metrics))

    plt.figure(figsize=(6, 4))
    plt.bar(x, values, color=palette[: len(metrics)])
    plt.xticks(x, metrics, rotation=20, ha="right")
    plt.ylabel("bits")
    plt.title(f"Entropy & MI for field {field_name}")
    plt.tight_layout()

    _ensure_dir(output_path)
    plt.savefig(output_path, format="pdf")
    plt.close()


# ===========================================================
#  5. PERCENTAGE OF DEVICES WITH UNIQUE OR NEARLY UNIQUE VALUES
# ===========================================================

def plot_unique_devices_percent_per_field(
    field_name: str,
    device_k: Mapping[str, int],
    output_path: str = "outputs/results/{field}_unique_devices_percent.pdf",
) -> None:
    """
    For a given field, plots:
        k  ->  % devices that have at least one value with k' <= k

    This is the graphical version of the "DEVICE perspective" section in the report.

    :param field_name: Field name (e.g., "HT_CAP").
    :param device_k: dict: device_id -> minimal k for that device
                      (from calculate_device_k_perspective).
    :param output_path: Path to save the file (may contain {field}).
    """
    output_path = output_path.format(field=field_name)

    if not device_k:
        # no data to plot
        return

    ks = sorted(set(device_k.values()))
    total_devices = len(device_k)

    x_vals = list(range(len(ks)))
    pcts = []
    for k in ks:
        num = sum(1 for mk in device_k.values() if mk <= k)
        pct = (num / total_devices) * 100.0
        pcts.append(pct)

    plt.figure(figsize=(6, 4))
    plt.bar(x_vals, pcts, color=_SINGLE_COLOR)
    plt.xticks(x_vals, ks)
    plt.xlabel("k (max devices per value)")
    plt.ylabel("Devices with at least one value (k' ≤ k) [%]")
    plt.title(f"Device perspective for field {field_name}")
    plt.tight_layout()

    _ensure_dir(output_path)
    plt.savefig(output_path, format="pdf")
    plt.close()


# ===========================================================
#  6. ANONIMITY SET SIZE DISTRIBUTION
# ===========================================================

_PRIVACY_DISTRIBUTION_CACHE = {
    "anonymity": None,
    "fingerprint": None,
}


def _get_shared_privacy_x_max():
    """
    Returns the joint maximum on the X-axis for:
    - anonymity set size distribution
    - fingerprint sharing distribution

    It operates based on data cached from the most recent calls
    to both functions.
    """
    max_values = []

    anonymity_entry = _PRIVACY_DISTRIBUTION_CACHE.get("anonymity")
    if anonymity_entry is not None:
        anonymity_data = anonymity_entry["data"]
        if anonymity_data:
            max_values.append(max(anonymity_data.keys()))

    fingerprint_entry = _PRIVACY_DISTRIBUTION_CACHE.get("fingerprint")
    if fingerprint_entry is not None:
        fingerprint_data = fingerprint_entry["data"]
        if fingerprint_data:
            max_values.append(max(fingerprint_data.keys()))

    if not max_values:
        return None

    return max(max_values)
    
def _plot_anonymity_set_sizes_core(
    anonymity_set_sizes: dict[int, int],
    output_path: str,
    x_max: int | None,
):
    xs = sorted(anonymity_set_sizes.keys())
    ys = [anonymity_set_sizes[x] for x in xs]

    if not xs:
        return

    positive_ys = [y for y in ys if y > 0]
    log_threshold = 100

    if positive_ys:
        min_y = min(positive_ys)
        max_y = max(positive_ys)
        use_log_scale = max_y / min_y >= log_threshold
    else:
        use_log_scale = False

    fig, ax = plt.subplots(figsize=(6.2, 3.6))

    ax.bar(
        xs,
        ys,
        width=_auto_bar_width(xs),
        color=_SINGLE_COLOR,
        edgecolor=_SINGLE_COLOR,
    )

    if use_log_scale:
        ax.set_yscale("log")
        ax.set_ylim(bottom=1)
    else:
        ax.set_ylim(bottom=0)

    _set_all_integer_xticks(ax, xs, x_max=x_max)

    ax.set_xlabel("Anonymity set size")
    ax.set_ylabel("Number of devices")

    _style_axis(ax)

    plt.tight_layout()
    plt.savefig(output_path, format="pdf")
    plt.close()

def plot_anonymity_set_sizes(
    anonymity_set_sizes: dict[int, int],
    title: str = "",  # left for compatibility
    output_path: str = "outputs/results/anonymity_set_sizes.pdf",
):
    _PRIVACY_DISTRIBUTION_CACHE["anonymity"] = {
        "data": dict(anonymity_set_sizes),
        "output_path": output_path,
    }

    shared_x_max = _get_shared_privacy_x_max()

    xs = sorted(anonymity_set_sizes.keys())
    ys = [anonymity_set_sizes[x] for x in xs]

    if not xs:
        return

    positive_ys = [y for y in ys if y > 0]
    log_threshold = 100

    if positive_ys:
        min_y = min(positive_ys)
        max_y = max(positive_ys)
        use_log_scale = max_y / min_y >= log_threshold
    else:
        use_log_scale = False

    fig, ax = plt.subplots(figsize=(6.2, 3.6))

    ax.bar(
        xs,
        ys,
        width=_auto_bar_width(xs),
        color=_SINGLE_COLOR,
        edgecolor=_SINGLE_COLOR,
    )

    if use_log_scale:
        ax.set_yscale("log")
        ax.set_ylim(bottom=1)
    else:
        ax.set_ylim(bottom=0)

    _set_all_integer_xticks(ax, xs, x_max=shared_x_max)

    ax.set_xlabel("Anonymity set size")
    ax.set_ylabel("Number of devices")

    _style_axis(ax)

    plt.tight_layout()
    plt.savefig(output_path, format="pdf")
    plt.close()

    # Jeśli fingerprint był już wcześniej narysowany z mniejszą osią X,
    # przerysuj go automatycznie z nowym wspólnym zakresem.
    fingerprint_entry = _PRIVACY_DISTRIBUTION_CACHE.get("fingerprint")
    if fingerprint_entry is not None:
        fingerprint_data = fingerprint_entry["data"]
        fingerprint_output_path = fingerprint_entry["output_path"]

        fingerprint_max = max(fingerprint_data.keys()) if fingerprint_data else 0
        anonymity_max = max(anonymity_set_sizes.keys()) if anonymity_set_sizes else 0

        if anonymity_max > fingerprint_max:
            _plot_fingerprint_sharing_distribution_core(
                fingerprint_data,
                fingerprint_output_path,
                shared_x_max,
            )


def _plot_fingerprint_sharing_distribution_core(
    fingerprint_sharing_distribution: dict[int, int],
    output_path: str,
    x_max: int | None,
):
    xs = sorted(fingerprint_sharing_distribution.keys())
    ys = [fingerprint_sharing_distribution[x] for x in xs]

    if not xs:
        return

    fig, ax = plt.subplots(figsize=(6.2, 3.6))

    ax.bar(
        xs,
        ys,
        width=_auto_bar_width(xs),
        color=_SINGLE_COLOR,
        edgecolor=_SINGLE_COLOR,
    )

    _set_all_integer_xticks(ax, xs, x_max=x_max)

    ax.set_xlabel("Number of devices sharing the same fingerprint")
    ax.set_ylabel("Number of fingerprints")

    if ys:
        ax.set_ylim(bottom=0, top=max(ys) * 1.15)
    else:
        ax.set_ylim(bottom=0)

    _style_axis(ax)

    plt.tight_layout()
    plt.savefig(output_path, format="pdf")
    plt.close()


def plot_fingerprint_sharing_distribution(
    fingerprint_sharing_distribution: dict[int, int],
    title: str = "",  # left for compatibility
    output_path: str = "outputs/results/fingerprint_sharing_distribution.pdf",
):
    _PRIVACY_DISTRIBUTION_CACHE["fingerprint"] = {
        "data": dict(fingerprint_sharing_distribution),
        "output_path": output_path,
    }

    shared_x_max = _get_shared_privacy_x_max()

    _plot_fingerprint_sharing_distribution_core(
        fingerprint_sharing_distribution,
        output_path,
        shared_x_max,
    )

    # If the anonymity was previously plotted with a smaller X-axis,
    # automatically redraw it with the new common range.
    anonymity_entry = _PRIVACY_DISTRIBUTION_CACHE.get("anonymity")
    if anonymity_entry is not None:
        anonymity_data = anonymity_entry["data"]
        anonymity_output_path = anonymity_entry["output_path"]

        fingerprint_max = (
            max(fingerprint_sharing_distribution.keys())
            if fingerprint_sharing_distribution
            else 0
        )
        anonymity_max = max(anonymity_data.keys()) if anonymity_data else 0

        if fingerprint_max > anonymity_max:
            _plot_anonymity_set_sizes_core(
                anonymity_data,
                anonymity_output_path,
                shared_x_max,
            )