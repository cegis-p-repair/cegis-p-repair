#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Run P-Repair on the per-service benchmark cases (experiments/s3, ec2, rds, lambda)
and summarize overall outcomes per (Service & Kind) row used in Table~\ref{tab:overall}.

Rows:
  - S3, identity
  - S3, resource
  - EC2, identity
  - RDS, identity
  - Lambda, resource

For each row we report:
  - number of cases
  - SatAll rate
  - average KeepRate
  - whether any P2 violations remain (Leakage indicator)
  - average Iters
"""

from __future__ import annotations

import copy
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Dict
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import policy_repair_z3_multi_io as pr  # noqa: E402


@dataclass
class CaseResult:
    sat_all: bool
    keep_rate: float
    has_leak: bool
    iters: int


def cegis_repair_profiled(exp: pr.Experiment, verbose: bool = False) -> Tuple[List[pr.Policy], int, bool]:
    """
    CEGIS loop with iteration counting, mirroring the main script semantics.
    Returns (repaired_policies, iters, sat_flag).
    """
    W: List[pr.Request] = []

    # Optional merge-based preprocessing
    try:
        P = pr.merge_policies_for_repair(exp.policies)
    except ValueError as e:
        if verbose:
            print(f"[Merge] Conflict detected: {e}")
            print("[Merge] Refusing to repair this input policy set.")
        return copy.deepcopy(exp.policies), 0, False

    P = copy.deepcopy(P)
    iters = 0
    sat = False

    for it in range(1, exp.max_iters + 1):
        iters = it
        res = pr.verify(P, exp.p1, exp.p2, exp.baseline)
        if res.sat:
            sat = True
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

        if verbose:
            for e in chosen:
                print(
                    f"  -> Apply {e.kind} on policy[{e.target.policy_idx}] "
                    f"sid={e.target.sid}: {e.payload}  (w={e.weight})"
                )
        P = pr.apply_edits(P, chosen)

    return P, iters, sat


def eval_case(path: Path, verbose: bool = False) -> CaseResult:
    exp = pr.PolicyLoader.load_json(str(path))
    repaired, iters, sat_flag = cegis_repair_profiled(exp, verbose=verbose)

    # Evaluate repaired policies
    metrics = pr.evaluate_policy(repaired, exp.p1, exp.p2, exp.baseline)
    sat_all = bool(metrics["sat_all"])
    baseline_viol = int(metrics["baseline_violations"])
    forb_viol = int(metrics["forbid_violations"])
    bsize = max(1, len(exp.baseline))
    keep_rate = 1.0 - (baseline_viol / bsize)
    has_leak = forb_viol > 0

    return CaseResult(
        sat_all=sat_all,
        keep_rate=keep_rate,
        has_leak=has_leak,
        iters=iters,
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
        # We assume experiments have a single policy per file.
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

    print(
        f"{label}: n={n}, SatAll={sat_rate:.3f}, "
        f"KeepRate={keep_avg:.3f}, LeakAny={int(leak_any)}, "
        f"Iters_avg={iters_avg:.2f}"
    )


def main() -> None:
    t0 = time.time()
    print("Summarizing RQ1 overall outcomes per Service & Kind\n")
    summarize_row("S3, identity", "s3", "identity")
    summarize_row("S3, resource", "s3", "resource")
    summarize_row("EC2, identity", "ec2", "identity")
    summarize_row("RDS, identity", "rds", "identity")
    summarize_row("Lambda, resource", "lambda", "resource")
    print(f"\nDone in {time.time() - t0:.2f}s")


if __name__ == "__main__":
    main()
