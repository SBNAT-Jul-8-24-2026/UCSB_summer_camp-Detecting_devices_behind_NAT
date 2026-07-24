from pathlib import Path
import json
import math

import matplotlib.pyplot as plt


base_dir = Path(__file__).resolve().parent


def dim_values(flow_dict: dict) -> tuple[list[int], list[float]]:
    """Empirical CDF of flows-per-IP.

    x: sorted flow counts for each IP
    y: fraction of IPs with count <= x[i]
    """
    counts = sorted(len(flows) for flows in flow_dict.values())
    n = len(counts)
    if n == 0:
        return [], []
    y = [(i + 1) / n for i in range(n)]
    return counts, y


def empiric_quantile(sorted_vals: list[int], p: float) -> int:
    """Return the empirical p-quantile from an already-sorted list."""
    n = len(sorted_vals)
    idx = min(max(math.ceil(p * n) - 1, 0), n - 1)
    return sorted_vals[idx]


def mark_quartile(ax, x_val: float, y_val: float, label: str) -> None:
    """Draw guide lines and annotate one quartile on the CDF."""
    ax.axvline(x_val, color="#c0504d", linestyle="--", linewidth=1, alpha=0.8)
    ax.axhline(y_val, color="#c0504d", linestyle="--", linewidth=1, alpha=0.5)
    ax.scatter([x_val], [y_val], color="#c0504d", zorder=5)
    ax.annotate(
        f"{label} = {x_val}",
        xy=(x_val, y_val),
        xytext=(12, -18),
        textcoords="offset points",
        fontsize=10,
        color="#c0504d",
        arrowprops={"arrowstyle": "->", "color": "#c0504d", "lw": 1},
    )


def cdf_graph(flow_dict: dict, output_path: Path | None = None) -> None:
    x, y = dim_values(flow_dict)
    if not x:
        raise ValueError("Dictionary is empty; nothing to plot.")

    q1 = empiric_quantile(x, 0.25)
    q3 = empiric_quantile(x, 0.75)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(x, y, drawstyle="steps-post", color="#1f4e79", linewidth=2)
    mark_quartile(ax, q1, 0.25, "Q1")
    mark_quartile(ax, q3, 0.75, "Q3")

    ax.set_xscale("log")
    ax.set_xlabel("Flows per UCSB IP (log scale)")
    ax.set_ylabel("CDF")
    ax.set_title("Empirical CDF of Flows per UCSB IP (log-x)")
    x_max = math.ceil(max(x))
    ax.set_ylim(0, 1.05)
    # log scale cannot include 0; flow counts start at 1
    ax.set_xlim(0.8, x_max)
    ax.grid(True, which="both", linestyle="--", alpha=0.4)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout()
    if output_path is not None:
        fig.savefig(output_path, dpi=150)
        print(f"Saved figure to {output_path}")
        print(f"Q1 (25%): {q1} flows/IP")
        print(f"Q3 (75%): {q3} flows/IP")
    plt.show()


if __name__ == "__main__":
    input_file = base_dir / "flows.json"
    output_file = base_dir / "flows_cdf.png"

    with input_file.open("r", encoding="utf-8") as file:
        flow_dict = json.load(file)

    cdf_graph(flow_dict, output_path=output_file)
