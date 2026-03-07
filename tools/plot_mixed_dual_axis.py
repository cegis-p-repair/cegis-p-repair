#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "outputs" / "perf_mixed_metrics.csv"

def load_family(family: str):
    rows = []
    with CSV.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["family"] != family:
                continue
            level = int(row["level"])
            iters = int(row["iters"])
            t_solve = float(row["t_solve"])
            t_total = float(row["t_total"])
            rows.append((level, iters, t_solve, t_total))
    rows.sort(key=lambda r: r[0])
    levels = [r[0] for r in rows]

    # Use cumulative values to smooth noise and highlight trends.
    iters_cum = []
    t_solve_cum = []
    t_total_cum = []
    ci = cs = ct = 0.0
    for _, it, ts, tt in rows:
        ci += it
        cs += ts
        ct += tt
        iters_cum.append(ci)
        t_solve_cum.append(cs)
        t_total_cum.append(ct)

    return levels, iters_cum, t_solve_cum, t_total_cum

def plot_family(family: str):
    levels, iters, t_solve, t_total = load_family(family)

    # 稍微宽一点的图，方便看
    fig, ax1 = plt.subplots(figsize=(3, 5))

    # 左轴：累计 Iters（线条加细、不要 marker）
    ax1.set_xlabel("level")
    ax1.set_ylabel("Iters", color="tab:blue")
    l1, = ax1.plot(
        levels,
        iters,
        color="tab:blue",
        linewidth=1,
        label="Iters",
    )
    ax1.tick_params(axis="y", labelcolor="tab:blue")

    # 右轴：累计时间
    ax2 = ax1.twinx()
    ax2.set_ylabel("Time (s)", color="tab:red")
    l2, = ax2.plot(
        levels,
        t_solve,
        color="tab:red",
        linewidth=1,
        linestyle="--",
        label="T_solve",
    )
    l3, = ax2.plot(
        levels,
        t_total,
        color="tab:green",
        linewidth=1,
        linestyle="-",
        label="T_total",
    )
    ax2.tick_params(axis="y", labelcolor="tab:red")

    # 图例：放在图内左上角
    lines = [l1, l2, l3]
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="upper left", frameon=False)

    fig.tight_layout()
    out_dir = ROOT / "outputs" / "plots"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"mixed_{family}_dualaxis.png"
    fig.savefig(out_path, dpi=400)
    plt.close(fig)
    print(f"saved {out_path}")

if __name__ == "__main__":
    for fam in ["statements", "wildcards", "universe"]:
        plot_family(fam)
