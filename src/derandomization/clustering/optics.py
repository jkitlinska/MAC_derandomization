from sklearn.cluster import OPTICS
import numpy as np
import matplotlib.pyplot as plt
import os
from matplotlib.lines import Line2D

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

def optics_clustering(distance_matrix):
    """
    Perform OPTICS clustering on the given distance matrix.

    Parameters:
    - distance_matrix: A 2D list or numpy array representing pairwise distances.
    - min_samples: Minimum number of samples in a neighborhood for a point to be considered as a core point.
    - eps: Maximum distance between two samples for one to be considered as in the neighborhood of the other.

    Returns:
    - labels: Cluster labels for each point in the dataset.
    """

    # Convert distance matrix to a numpy array if it's not already
    distance_matrix = np.array(distance_matrix)

    # Create an OPTICS clustering model
    optics_model = OPTICS(min_samples=2, xi=0.05, min_cluster_size=15, metric='precomputed')

    # Fit the model to the distance matrix
    optics_model.fit(distance_matrix)

    # Return the cluster labels
    return optics_model, optics_model.labels_

def plot_optics_reachability(optics_model, labels, name, bar_threshold=0.01):
    """
    Plot the reachability plot for the OPTICS model.
    Text and axis styling is consistent with fingerprint_sharing_distribution.
    Cluster colors remain contrastive.
    """

    ordering = optics_model.ordering_
    reachability = optics_model.reachability_[ordering]
    labels_ordered = optics_model.labels_[ordering]

    x = np.arange(len(reachability))

    fig, ax = plt.subplots(figsize=(6.2, 3.6))

    cluster_labels = [k for k in np.unique(labels_ordered) if k != -1]
    n_clusters = len(cluster_labels)

    cmap = plt.cm.hsv
    base_colors = cmap(np.linspace(0, 1, n_clusters, endpoint=False))

    step = max(1, n_clusters // 2 - 1)
    if n_clusters > 0 and np.gcd(step, n_clusters) != 1:
        step = 7 if n_clusters > 7 else 1

    color_order = [(i * step) % n_clusters for i in range(n_clusters)]
    colors = base_colors[color_order] if n_clusters > 0 else []

    color_map = {
        klass: colors[i]
        for i, klass in enumerate(cluster_labels)
    }

    for klass in np.unique(labels_ordered):
        mask = labels_ordered == klass
        finite_mask = mask & np.isfinite(reachability)

        if klass == -1:
            ax.plot(
                x[finite_mask],
                reachability[finite_mask],
                marker="x",
                linestyle="",
                color="lightgray",
                markersize=4,
            )
            continue

        color = color_map[klass]

        small_mask = finite_mask & (reachability <= bar_threshold)
        large_mask = finite_mask & (reachability > bar_threshold)

        ax.vlines(
            x[large_mask],
            ymin=0,
            ymax=reachability[large_mask],
            colors=color,
            linewidth=1.0,
        )

        ax.plot(
            x[small_mask],
            reachability[small_mask],
            marker="s",
            linestyle="",
            color=color,
            markersize=2.5,
        )

    ax.set_xlabel("Ordered point index")
    ax.set_ylabel("Reachability distance")

    ax.set_xlim(-0.5, len(reachability) - 0.5)
    ax.set_ylim(bottom=0)

    ax.set_axisbelow(True)

    ax.grid(
        True,
        which="major",
        axis="both",
        color="#d9d9d9",
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

    ax.margins(y=0)

    legend_elements = [
        Line2D(
            [0], [0],
            color="black",
            linewidth=2,
            label="Cluster",
        ),
        Line2D(
            [0], [0],
            marker="x",
            color="lightgray",
            linestyle="",
            markersize=5,
            label="Noise",
        ),
    ]

    ax.legend(handles=legend_elements, frameon=True)

    plt.tight_layout()

    output_path = f"plots/reachability_plot_{name}.pdf"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path, format="pdf")
    plt.close()
    
def extract_clusters(optics_model, macs):
    """
    Extract clusters from the fitted OPTICS model.

    Parameters:
    - optics_model: Fitted OPTICS model.

    Returns:
    - clusters: A dictionary mapping cluster labels to lists of point indices.
    """

    clusters = {}
    for idx, label in enumerate(optics_model.labels_):
        if label not in clusters:
            clusters[label] = []
        clusters[label].append(macs[idx])
    
    return clusters
