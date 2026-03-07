#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RQ4: Ablation and comparison of edit-selection strategies.

This script runs several variants of the repair loop on the per-service
benchmarks (experiments/s3, ec2, rds, lambda) and summarizes, for each
(Service & Kind, Mode) combination:

  - SatAll rate and average KeepRate
  - average iteration count
  - total edit counts (#R2, #R3, #R1, #R4-style) and EditCost

Modes currently implemented:

  - default      : MaxSMT hitting-set (same as RQ1/RQ2).
  - greedy_r2r3  : greedy single-edit per witness, preferring R2/R3.
  - greedy_r1    : greedy single-edit per witness, preferring R1.
  - deny_only    : greedy with deny edits only (R4).
  - no_priority  : MaxSMT, but witnesses prioritize P1 before P2.
"""

from __future__ import annotations

import copy
import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import policy_repair_z3_multi_io as pr  # noqa: E402


OUT_DIR = ROOT / "outputs"
OUT_CSV = OUT_DIR / "rq4_ablation.csv"


MODES = ["default", "greedy_r2r3", "greedy_r1", "deny_only", "no_priority"]


@dataclass
class EditStats:
    counts: Dict[str, int] = field(default_factory=lambda: {"R1": 0, "R2": 0, "R3": 0, "R4": 0})
    cost: int = 0

    def add_edit(self, e: pr.Edit) -> None:
        self.counts[e.kind] = self.counts.get(e.kind, 0) + 1
        self.cost += int(e.weight)


@dataclass
class CaseResult:
    mode: str
    label: str
    service: str
    kind: str
    sat_all: bool
    keep_rate: float
    has_leak: bool
    iters: int
    edits: EditStats


def verify_no_priority(policies: List[pr.Policy], p1: pr.AllowEnvelope, p2: pr.ForbidSlice,
                       baseline: List[pr.Request]) -> pr.VerifyResult:
    """
    Variant of pr.verify that checks P1 envelope before P2 forbidden slice.
    Baseline checks and universe construction remain identical.
    """
    # Baseline must pass
    for b in baseline:
        if not pr.permit(policies, b):
            return pr.VerifyResult(sat=False, witness=b, kind="Baseline")

    principals, actions, resources = pr.build_universe(policies, p1, p2, baseline)

    # P1 envelope first: any permitted request must be inside the envelope.
    for p in principals:
        for a in actions:
            for r in resources:
                q = pr.Request(principal=p, action=a, resource=r, gamma={})
                if pr.permit(policies, q) and (not p1.in_envelope(q)):
                    return pr.VerifyResult(sat=False, witness=q, kind="P1")

    # Then P2 forbidden slice.
    for p in principals:
        for a in actions:
            for r in resources:
                q = pr.Request(principal=p, action=a, resource=r, gamma={})
                if pr.permit(policies, q) and p2.is_forbidden(q):
                    return pr.VerifyResult(sat=False, witness=q, kind="P2")

    return pr.VerifyResult(sat=True)


def run_default(exp: pr.Experiment, verbose: bool = False) -> Tuple[List[pr.Policy], int, EditStats]:
    """
    Default MaxSMT-based loop (same semantics as in run_rq1_overall / run_rq2_edits),
    with edit logging.
    """
    W: List[pr.Request] = []
    stats = EditStats()

    try:
        P0 = pr.merge_policies_for_repair(exp.policies)
    except ValueError as e:
        if verbose:
            print(f"[Merge] Conflict detected: {e}")
            print("[Merge] Refusing to repair this input policy set.")
        return copy.deepcopy(exp.policies), 0, stats

    P = copy.deepcopy(P0)
    iters = 0

    for it in range(1, exp.max_iters + 1):
        iters = it
        res = pr.verify(P, exp.p1, exp.p2, exp.baseline)
        if res.sat:
            break

        w = res.witness
        assert w is not None
        W.append(w)
        if verbose:
            print(f"[Iter {it}] Witness({res.kind}): principal={w.principal}, action={w.action}, resource={w.resource}")

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

    return P, iters, stats


def select_greedy_edit(P: List[pr.Policy], w: pr.Request, baseline: List[pr.Request],
                       allowed_kinds: List[str], weights: Dict[str, int] | None = None) -> List[pr.Edit]:
    """
    Greedy selection: pick a single edit for witness w that:
      - belongs to allowed_kinds (if non-empty),
      - kills the witness without breaking the baseline.
    """
    candidates = pr.generate_candidates(P, w, baseline, weights)
    pool: List[pr.Edit] = []
    for e in candidates:
        if allowed_kinds and e.kind not in allowed_kinds:
            continue
        if not pr.kills_witness(P, e, w, baseline):
            continue
        pool.append(e)

    if not pool:
        return []

    # Smallest weight, tie-broken by original order.
    best = min(pool, key=lambda e: int(e.weight))
    return [best]


def run_greedy(exp: pr.Experiment, mode: str, verbose: bool = False) -> Tuple[List[pr.Policy], int, EditStats]:
    """
    Greedy variants that apply at most one edit per iteration.
    """
    stats = EditStats()

    try:
        P0 = pr.merge_policies_for_repair(exp.policies)
    except ValueError as e:
        if verbose:
            print(f"[Merge] Conflict detected: {e}")
            print("[Merge] Refusing to repair this input policy set.")
        return copy.deepcopy(exp.policies), 0, stats

    P = copy.deepcopy(P0)
    iters = 0

    for it in range(1, exp.max_iters + 1):
        iters = it
        res = pr.verify(P, exp.p1, exp.p2, exp.baseline)
        if res.sat:
            break

        w = res.witness
        assert w is not None
        if verbose:
            print(f"[Iter {it}] Witness({res.kind}): principal={w.principal}, action={w.action}, resource={w.resource}")

        if mode == "greedy_r2r3":
            allowed = ["R2", "R3"]
        elif mode == "greedy_r1":
            allowed = ["R1"]
        elif mode == "deny_only":
            allowed = ["R4"]
        else:
            allowed = []

        chosen = select_greedy_edit(P, w, exp.baseline, allowed, exp.weights)
        if not chosen:
            if verbose:
                print(f"[Iter {it}] No greedy edit available. Stop.")
            break

        for e in chosen:
            stats.add_edit(e)
            if verbose:
                print(
                    f"  -> Apply {e.kind} on policy[{e.target.policy_idx}] "
                    f"sid={e.target.sid}: {e.payload}  (w={e.weight})"
                )
        P = pr.apply_edits(P, chosen)

    return P, iters, stats


def run_no_priority(exp: pr.Experiment, verbose: bool = False) -> Tuple[List[pr.Policy], int, EditStats]:
    """
    MaxSMT loop that differs from the default only in the order of
    P1/P2 checks in the verifier (P1 before P2).
    """
    W: List[pr.Request] = []
    stats = EditStats()

    try:
        P0 = pr.merge_policies_for_repair(exp.policies)
    except ValueError as e:
        if verbose:
            print(f"[Merge] Conflict detected: {e}")
            print("[Merge] Refusing to repair this input policy set.")
        return copy.deepcopy(exp.policies), 0, stats

    P = copy.deepcopy(P0)
    iters = 0

    for it in range(1, exp.max_iters + 1):
        iters = it
        res = verify_no_priority(P, exp.p1, exp.p2, exp.baseline)
        if res.sat:
            break

        w = res.witness
        assert w is not None
        W.append(w)
        if verbose:
            print(f"[Iter {it}] Witness({res.kind}): principal={w.principal}, action={w.action}, resource={w.resource}")

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

    return P, iters, stats


def run_variant(exp: pr.Experiment, mode: str, verbose: bool = False) -> Tuple[List[pr.Policy], int, EditStats]:
    if mode == "default":
        return run_default(exp, verbose=verbose)
    if mode in ("greedy_r2r3", "greedy_r1", "deny_only"):
        return run_greedy(exp, mode=mode, verbose=verbose)
    if mode == "no_priority":
        return run_no_priority(exp, verbose=verbose)
    raise ValueError(f"Unknown mode: {mode}")


def collect_cases(service: str, kind: str) -> List[Path]:
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


def eval_case(path: Path, label: str, service: str, kind: str, mode: str) -> CaseResult:
    exp = pr.PolicyLoader.load_json(str(path))
    repaired, iters, stats = run_variant(exp, mode=mode, verbose=False)

    metrics = pr.evaluate_policy(repaired, exp.p1, exp.p2, exp.baseline)
    sat_all = bool(metrics["sat_all"])
    baseline_viol = int(metrics["baseline_violations"])
    forb_viol = int(metrics["forbid_violations"])
    bsize = max(1, len(exp.baseline))
    keep_rate = 1.0 - (baseline_viol / bsize)
    has_leak = forb_viol > 0

    return CaseResult(
        mode=mode,
        label=label,
        service=service,
        kind=kind,
        sat_all=sat_all,
        keep_rate=keep_rate,
        has_leak=has_leak,
        iters=iters,
        edits=stats,
    )


def summarize_row(label: str, service: str, kind: str, writer) -> None:
    paths = collect_cases(service, kind)
    if not paths:
        print(f"{label}: no cases found")
        return

    for mode in MODES:
        results: List[CaseResult] = []
        for p in paths:
            results.append(eval_case(p, label=label, service=service, kind=kind, mode=mode))

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
            f"{label} [{mode}]: n={n}, SatAll={sat_rate:.3f}, KeepRate={keep_avg:.3f}, "
            f"LeakAny={int(leak_any)}, Iters_avg={iters_avg:.2f}, "
            f"#R2={r2}, #R3={r3}, #R1={r1}, #R4={r4}, EditCost={total_cost}"
        )

        writer.writerow(
            [
                label,
                service,
                kind,
                mode,
                n,
                f"{sat_rate:.3f}",
                f"{keep_avg:.3f}",
                int(leak_any),
                f"{iters_avg:.2f}",
                r2,
                r3,
                r1,
                r4,
                total_cost,
            ]
        )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "label",
                "service",
                "kind",
                "mode",
                "num_cases",
                "sat_rate",
                "keep_rate_avg",
                "leak_any",
                "iters_avg",
                "R2_total",
                "R3_total",
                "R1_total",
                "R4_total",
                "edit_cost_total",
            ]
        )

        print("Running RQ4 ablation modes over per-service benchmarks\n")
        summarize_row("S3, identity", "s3", "identity", writer)
        summarize_row("S3, resource", "s3", "resource", writer)
        summarize_row("EC2, identity", "ec2", "identity", writer)
        summarize_row("RDS, identity", "rds", "identity", writer)
        summarize_row("Lambda, resource", "lambda", "resource", writer)

    print(f"\nAblation results written to {OUT_CSV}")


if __name__ == "__main__":
    main()
