#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RQ5: Authorization-time overhead of repaired policies.

This script measures the micro-level authorization cost of the policy sets
before and after repair using the prototype's `permit()` evaluator.
For each benchmark row used in the paper, it reports:

  - average authorization time per request (microseconds),
  - relative overhead after repair,
  - average statement / deny / condition-atom deltas.

Outputs:
  - outputs/authz_overhead.csv
  - outputs/plots/authz_overhead_pct.png
"""

from __future__ import annotations

import copy
import csv
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import policy_repair_z3_multi_io as pr  # noqa: E402

try:
    import matplotlib.pyplot as plt
except Exception:
    plt = None


OUT_DIR = ROOT / "outputs"
PLOT_DIR = OUT_DIR / "plots"
OUT_CSV = OUT_DIR / "authz_overhead.csv"
OUT_PNG = PLOT_DIR / "authz_overhead_pct.png"

ROWS: List[Tuple[str, str, str]] = [
    ("S3, identity", "s3", "identity"),
    ("S3, resource", "s3", "resource"),
    ("EC2, identity", "ec2", "identity"),
    ("RDS, identity", "rds", "identity"),
    ("Lambda, resource", "lambda", "resource"),
]


@dataclass
class CaseMetrics:
    label: str
    case: str
    workload_size: int
    rounds: int
    orig_us: float
    repaired_us: float
    delta_pct: float
    stmt_delta: int
    deny_delta: int
    cond_delta: int


@dataclass
class RowMetrics:
    label: str
    service: str
    kind: str
    num_cases: int
    workload_size_avg: float
    orig_us_avg: float
    repaired_us_avg: float
    delta_pct_avg: float
    stmt_delta_avg: float
    deny_delta_avg: float
    cond_delta_avg: float


def collect_cases(service: str, kind: str) -> List[Path]:
    base = ROOT / "experiments" / service
    if not base.is_dir():
        raise SystemExit(f"Directory not found: {base}. Run tools/generate_experiments.py first.")

    out: List[Path] = []
    for path in sorted(base.glob("case_*.json")):
        exp = pr.PolicyLoader.load_json(str(path))
        if exp.policies[0].kind == kind:
            out.append(path)
    return out


def structural_counts(policies: List[pr.Policy]) -> Tuple[int, int, int]:
    stmt_count = 0
    deny_count = 0
    cond_atoms = 0
    for pol in policies:
        for stmt in pol.statements:
            stmt_count += 1
            if stmt.effect == "Deny":
                deny_count += 1
            cond_atoms += len(stmt.conditions)
    return stmt_count, deny_count, cond_atoms


def dedup_requests(requests: Iterable[pr.Request]) -> List[pr.Request]:
    seen = set()
    out: List[pr.Request] = []
    for req in requests:
        key = (
            req.principal,
            req.action,
            req.resource,
            tuple(sorted((k, str(v)) for k, v in req.gamma.items())),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(req)
    return out


def build_workload(exp: pr.Experiment) -> List[pr.Request]:
    principals, actions, resources = pr.build_universe(exp.policies, exp.p1, exp.p2, exp.baseline)
    requests = list(exp.baseline)
    for principal in sorted(principals):
        for action in sorted(actions):
            for resource in sorted(resources):
                requests.append(pr.Request(principal=principal, action=action, resource=resource, gamma={}))
    return dedup_requests(requests)


def choose_rounds(workload_size: int, target_calls: int = 20000) -> int:
    return max(20, math.ceil(target_calls / max(1, workload_size)))


def benchmark_permit(policies: List[pr.Policy], workload: List[pr.Request], rounds: int) -> float:
    for _ in range(5):
        for req in workload:
            pr.permit(policies, req)

    start = time.perf_counter()
    sink = 0
    for _ in range(rounds):
        for req in workload:
            sink += int(pr.permit(policies, req))
    elapsed = time.perf_counter() - start

    if sink < 0:
        raise AssertionError("unreachable sink guard")

    calls = rounds * max(1, len(workload))
    return elapsed * 1_000_000.0 / calls


def evaluate_case(label: str, path: Path) -> CaseMetrics:
    exp = pr.PolicyLoader.load_json(str(path))
    repaired = pr.cegis_repair(
        exp.policies,
        exp.p1,
        exp.p2,
        exp.baseline,
        weights=exp.weights,
        max_iters=exp.max_iters,
        verbose=False,
    )

    workload = build_workload(exp)
    rounds = choose_rounds(len(workload))

    orig_stmt, orig_deny, orig_cond = structural_counts(exp.policies)
    repaired_stmt, repaired_deny, repaired_cond = structural_counts(repaired)

    orig_us = benchmark_permit(exp.policies, workload, rounds)
    repaired_us = benchmark_permit(repaired, workload, rounds)
    delta_pct = ((repaired_us - orig_us) / orig_us * 100.0) if orig_us else 0.0

    return CaseMetrics(
        label=label,
        case=path.stem,
        workload_size=len(workload),
        rounds=rounds,
        orig_us=orig_us,
        repaired_us=repaired_us,
        delta_pct=delta_pct,
        stmt_delta=repaired_stmt - orig_stmt,
        deny_delta=repaired_deny - orig_deny,
        cond_delta=repaired_cond - orig_cond,
    )


def average(values: Iterable[float]) -> float:
    items = list(values)
    return sum(items) / max(1, len(items))


def summarize_row(label: str, service: str, kind: str) -> RowMetrics:
    paths = collect_cases(service, kind)
    print(f"[RQ5] Measuring {label} over {len(paths)} cases...")
    cases = [evaluate_case(label, path) for path in paths]
    return RowMetrics(
        label=label,
        service=service,
        kind=kind,
        num_cases=len(cases),
        workload_size_avg=average(case.workload_size for case in cases),
        orig_us_avg=average(case.orig_us for case in cases),
        repaired_us_avg=average(case.repaired_us for case in cases),
        delta_pct_avg=average(case.delta_pct for case in cases),
        stmt_delta_avg=average(case.stmt_delta for case in cases),
        deny_delta_avg=average(case.deny_delta for case in cases),
        cond_delta_avg=average(case.cond_delta for case in cases),
    )


def write_csv(rows: List[RowMetrics]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "label",
            "service",
            "kind",
            "num_cases",
            "workload_size_avg",
            "orig_us_avg",
            "repaired_us_avg",
            "delta_pct_avg",
            "stmt_delta_avg",
            "deny_delta_avg",
            "cond_delta_avg",
        ])
        for row in rows:
            writer.writerow([
                row.label,
                row.service,
                row.kind,
                row.num_cases,
                f"{row.workload_size_avg:.2f}",
                f"{row.orig_us_avg:.4f}",
                f"{row.repaired_us_avg:.4f}",
                f"{row.delta_pct_avg:.2f}",
                f"{row.stmt_delta_avg:.2f}",
                f"{row.deny_delta_avg:.2f}",
                f"{row.cond_delta_avg:.2f}",
            ])


def maybe_plot(rows: List[RowMetrics]) -> None:
    if plt is None:
        return

    PLOT_DIR.mkdir(parents=True, exist_ok=True)
    labels = [row.label for row in rows]
    values = [row.delta_pct_avg for row in rows]

    fig, ax = plt.subplots(figsize=(5.6, 2.8))
    bars = ax.bar(labels, values, color="#4C78A8")
    ax.axhline(0.0, color="black", linewidth=0.8)
    ax.set_ylabel("Latency delta (%)")
    ax.set_title("Authorization-time overhead after repair")
    ax.tick_params(axis="x", rotation=18)

    for bar, value in zip(bars, values):
        y = value + (0.5 if value >= 0 else -1.2)
        va = "bottom" if value >= 0 else "top"
        ax.text(bar.get_x() + bar.get_width() / 2, y, f"{value:.1f}", ha="center", va=va, fontsize=8)

    fig.tight_layout()
    fig.savefig(OUT_PNG, dpi=300)
    plt.close(fig)


def main() -> None:
    rows = [summarize_row(label, service, kind) for label, service, kind in ROWS]
    write_csv(rows)
    maybe_plot(rows)

    print(f"Wrote authorization-overhead summary to {OUT_CSV}")
    if OUT_PNG.exists():
        print(f"Saved plot to {OUT_PNG}")
    for row in rows:
        print(
            f"{row.label}: orig={row.orig_us_avg:.4f}us, repaired={row.repaired_us_avg:.4f}us, "
            f"delta={row.delta_pct_avg:.2f}%, stmtΔ={row.stmt_delta_avg:.2f}, "
            f"denyΔ={row.deny_delta_avg:.2f}, condΔ={row.cond_delta_avg:.2f}"
        )


if __name__ == "__main__":
    main()
