#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RQ2: Edit breakdown and EditCost.

This script runs the repair loop on the per-service benchmarks used for RQ1
and aggregates, for each (Service & Kind) row:

  - total counts of R2 / R3 / R1 / R4 edits, and
  - total EditCost = sum_e w(e) across all applied edits.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import policy_repair_z3_multi_io as pr  # noqa: E402


@dataclass
class EditStats:
    """Per-case edit statistics."""

    counts: Dict[str, int] = field(default_factory=lambda: {"R1": 0, "R2": 0, "R3": 0, "R4": 0})
    cost: int = 0

    def add_edit(self, e: pr.Edit) -> None:
        self.counts[e.kind] = self.counts.get(e.kind, 0) + 1
        self.cost += int(e.weight)


@dataclass
class CaseResult:
    iters: int
    sat_all: bool
    keep_rate: float
    has_leak: bool
    edits: EditStats


def cegis_repair_with_edits(exp: pr.Experiment, verbose: bool = False) -> Tuple[List[pr.Policy], int, EditStats, bool]:
    """
    CEGIS loop that mirrors the main semantics but additionally logs
    applied edits and their total cost.
    """
    W: List[pr.Request] = []
    stats = EditStats()

    # Optional merge-based preprocessing as in the main script.
    try:
        P0 = pr.merge_policies_for_repair(exp.policies)
    except ValueError as e:
        if verbose:
            print(f"[Merge] Conflict detected: {e}")
            print("[Merge] Refusing to repair this input policy set.")
        return copy.deepcopy(exp.policies), 0, stats, False

    P = copy.deepcopy(P0)
    iters = 0
    sat_flag = False

    for it in range(1, exp.max_iters + 1):
        iters = it
        res = pr.verify(P, exp.p1, exp.p2, exp.baseline)
        if res.sat:
            sat_flag = True
            break

        w = res.witness
        assert w is not None
        W.append(w)
        if verbose:
            print(f"[Iter {it}] Witness({res.kind}): principal={w.principal}, action={w.action}, resource={w.resource}")

        # Rebuild candidates from all witnesses on current P
        E: List[pr.Edit] = []
        for u in W:
            E.extend(pr.generate_candidates(P, u, exp.baseline, exp.weights))

        if verbose:
            print(
                f"[Iter {it}] Candidates: {len(E)}  "
                + ", ".join(f"{e.kind}:{e.weight}@pol{e.target.policy_idx}:{e.target.sid}" for e in E)
            )

        chosen = pr.pick_min_cost_edits(P, W, exp.baseline, E)
        if not chosen:
            if verbose:
                print(f"[Iter {it}] No feasible edit set found. Stop.")
            break

        for e in chosen:
            stats.add_edit(e)
            if verbose:
                print(
                    f"  -> Apply {e.kind} on policy[{e.target.policy_idx}] "
                    f"sid={e.target.sid}: {e.payload}  (w={e.weight})"
                )
        P = pr.apply_edits(P, chosen)

    return P, iters, stats, sat_flag


def eval_case(path: Path, verbose: bool = False) -> CaseResult:
    exp = pr.PolicyLoader.load_json(str(path))
    repaired, iters, stats, sat_flag = cegis_repair_with_edits(exp, verbose=verbose)

    metrics = pr.evaluate_policy(repaired, exp.p1, exp.p2, exp.baseline)
    sat_all = bool(metrics["sat_all"])
    baseline_viol = int(metrics["baseline_violations"])
    forb_viol = int(metrics["forbid_violations"])
    bsize = max(1, len(exp.baseline))
    keep_rate = 1.0 - (baseline_viol / bsize)
    has_leak = forb_viol > 0

    return CaseResult(
        iters=iters,
        sat_all=sat_all,
        keep_rate=keep_rate,
        has_leak=has_leak,
        edits=stats,
    )


def collect_cases(service: str, kind: str) -> List[Path]:
    """
    Collect experiment JSONs from experiments/<service>/case_*.json
    filtered by policy kind ('identity' or 'resource').
    """
    base = ROOT / "experiments" / service
    if not base.is_dir():
        raise SystemExit(f"Directory not found: {base}. Run tools/generate_experiments.py first.")

    out: List[Path] = []
    for path in sorted(base.glob("case_*.json")):
        exp = pr.PolicyLoader.load_json(str(path))
        pol = exp.policies[0]
        if pol.kind == kind:
            out.append(path)
    return out


def summarize_row(label: str, service: str, kind: str) -> None:
    paths = collect_cases(service, kind)
    if not paths:
        print(f"{label}: no cases found")
        return

    results: List[CaseResult] = []
    for p in paths:
        results.append(eval_case(p, verbose=False))

    n = len(results)
    sat_rate = sum(1 for r in results if r.sat_all) / n
    keep_avg = sum(r.keep_rate for r in results) / n
    leak_any = any(r.has_leak for r in results)
    iters_avg = sum(r.iters for r in results) / n

    total_counts: Dict[str, int] = {"R1": 0, "R2": 0, "R3": 0, "R4": 0}
    total_cost = 0
    for r in results:
        for k, v in r.edits.counts.items():
            total_counts[k] = total_counts.get(k, 0) + v
        total_cost += r.edits.cost

    r2 = total_counts.get("R2", 0)
    r3 = total_counts.get("R3", 0)
    r1 = total_counts.get("R1", 0)
    r4 = total_counts.get("R4", 0)

    print(
        f"{label}: n={n}, SatAll={sat_rate:.3f}, KeepRate={keep_avg:.3f}, "
        f"LeakAny={int(leak_any)}, Iters_avg={iters_avg:.2f}, "
        f"#R2={r2}, #R3={r3}, #R1={r1}, #R4={r4}, EditCost={total_cost}"
    )


def main() -> None:
    print("RQ2 edit breakdown and EditCost per Service & Kind\n")
    summarize_row("S3, identity", "s3", "identity")
    summarize_row("S3, resource", "s3", "resource")
    summarize_row("EC2, identity", "ec2", "identity")
    summarize_row("RDS, identity", "rds", "identity")
    summarize_row("Lambda, resource", "lambda", "resource")


if __name__ == "__main__":
    main()
