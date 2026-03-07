#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate mixed-service performance experiment JSONs for PolicyRepair.

Unlike the per-service generators, this script does not expose the
service type as an explicit dimension. For each synthetic family
(statements, wildcards, universe) and each level 1..100, we sample
one benchmark from the union of S3/EC2/RDS/Lambda cases.

Output layout (relative to repo root):
  experiments/perf/mixed/statements_XXX.json
  experiments/perf/mixed/wildcards_XXX.json
  experiments/perf/mixed/universe_XXX.json
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Dict, List, Tuple

from generate_perf_ec2 import (
    gen_ec2_perf_statements,
    gen_ec2_perf_wildcards,
    gen_ec2_perf_universe,
)
from generate_perf_s3 import (
    gen_s3_perf_statements,
    gen_s3_perf_wildcards,
    gen_s3_perf_universe,
)
from generate_perf_rds import (
    gen_rds_perf_statements,
    gen_rds_perf_wildcards,
    gen_rds_perf_universe,
)
from generate_perf_lambda import (
    gen_lambda_perf_statements,
    gen_lambda_perf_wildcards,
    gen_lambda_perf_universe,
)


ROOT = Path(__file__).resolve().parents[1]
EXP_DIR = ROOT / "experiments"
PERF_MIXED_DIR = EXP_DIR / "perf" / "mixed"


def sample_family(
    pools: List[List[Tuple[str, Dict]]],
    count: int,
    seed: int,
) -> List[Dict]:
    """
    Flatten a list of (rel, obj) pools, and sample `count` experiment
    objects uniformly at random (without replacement) using a fixed seed.
    """
    all_exps: List[Dict] = []
    for pool in pools:
        all_exps.extend(obj for _rel, obj in pool)

    if not all_exps:
        raise ValueError("No experiments available to sample from.")

    rnd = random.Random(seed)
    # If we have enough distinct experiments, sample without replacement;
    # otherwise allow repetition (sampling with replacement) to reach `count`.
    if count <= len(all_exps):
        return rnd.sample(all_exps, count)
    return [rnd.choice(all_exps) for _ in range(count)]


def main() -> None:
    PERF_MIXED_DIR.mkdir(parents=True, exist_ok=True)

    # --- Collect per-service pools for each family ---
    # Statements: 1..100 per service
    s3_stmts = gen_s3_perf_statements(levels=range(1, 101))
    ec2_stmts = gen_ec2_perf_statements(levels=range(1, 101))
    rds_stmts = gen_rds_perf_statements(levels=range(1, 101))
    lambda_stmts = gen_lambda_perf_statements(levels=range(1, 101))

    # Wildcards: 100 per service
    s3_wild = gen_s3_perf_wildcards(count=100)
    ec2_wild = gen_ec2_perf_wildcards(count=100)
    rds_wild = gen_rds_perf_wildcards(count=100)
    lambda_wild = gen_lambda_perf_wildcards(count=100)

    # Universe: 100 per service (sizes 10..1000)
    sizes = [10 * i for i in range(1, 101)]
    s3_uni = gen_s3_perf_universe(sizes=sizes)
    ec2_uni = gen_ec2_perf_universe(sizes=sizes)
    rds_uni = gen_rds_perf_universe(sizes=sizes)
    lambda_uni = gen_lambda_perf_universe(sizes=sizes)

    # --- Sample mixed families (1000 levels each) ---
    stmts_mixed = sample_family(
        [s3_stmts, ec2_stmts, rds_stmts, lambda_stmts],
        count=1000,
        seed=20250101,
    )
    wild_mixed = sample_family(
        [s3_wild, ec2_wild, rds_wild, lambda_wild],
        count=1000,
        seed=20250102,
    )
    uni_mixed = sample_family(
        [s3_uni, ec2_uni, rds_uni, lambda_uni],
        count=1000,
        seed=20250103,
    )

    # --- Write out mixed experiments with new paths ---
    cases: List[Tuple[str, Dict]] = []
    for i, obj in enumerate(stmts_mixed, start=1):
        cases.append((f"perf/mixed/statements_{i:03d}.json", obj))
    for i, obj in enumerate(wild_mixed, start=1):
        cases.append((f"perf/mixed/wildcards_{i:03d}.json", obj))
    for i, obj in enumerate(uni_mixed, start=1):
        cases.append((f"perf/mixed/universe_{i:03d}.json", obj))

    for rel, obj in cases:
        path = EXP_DIR / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    print(f"Generated {len(cases)} mixed perf experiments under {PERF_MIXED_DIR}")


if __name__ == "__main__":
    main()
