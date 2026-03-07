#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate RDS-focused performance experiment JSONs for PolicyRepair.

Dimensions:
  1) Number of statements.
  2) Wildcard breadth in RDS actions.
  3) Universe size (number of DB ARNs in baseline).

Output layout:
  experiments/perf/rds/statements_XXX.json
  experiments/perf/rds/wildcards_XXX.json
  experiments/perf/rds/universe_XXXX.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
import random

from generate_experiments import (
    allow_env,
    baseline_req,
    forbid_slice,
    res_policy,
    stmt,
)


ROOT = Path(__file__).resolve().parents[1]
EXP_DIR = ROOT / "experiments"
PERF_RDS_DIR = EXP_DIR / "perf" / "rds"


def _base_rds_constants() -> Dict[str, Any]:
    acct = "111111111111"
    region = "us-east-1"
    user_alice = f"arn:aws:iam::{acct}:user/alice"
    db_any_prefix = f"arn:aws:rds:{region}:{acct}:db:"
    db_good = f"{db_any_prefix}appdb01"
    db_prod_prefix = f"{db_any_prefix}proddb"

    read_actions = ["rds:DescribeDBInstances", "rds:ListTagsForResource"]
    write_actions = ["rds:CreateDBInstance", "rds:DeleteDBInstance", "rds:ModifyDBInstance"]

    return {
        "acct": acct,
        "region": region,
        "user_alice": user_alice,
        "db_any_prefix": db_any_prefix,
        "db_good": db_good,
        "db_prod_prefix": db_prod_prefix,
        "read_actions": read_actions,
        "write_actions": write_actions,
    }


def gen_rds_perf_statements(levels: Iterable[int]) -> List[Tuple[str, Dict[str, Any]]]:
    c = _base_rds_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    for n in levels:
        random.seed(3444 + int(n))

        statements: List[Dict[str, Any]] = []

        # Core broad statement.
        core_actions = ["rds:DescribeDBInstances", "rds:ModifyDBInstance"]
        statements.append(
            stmt(
                sid="S1",
                effect="Allow",
                actions=core_actions,
                resources=[c["db_any_prefix"] + "*"],
                principals=[c["user_alice"]],
            )
        )

        base_actions = c["read_actions"] + c["write_actions"]

        for i in range(2, n + 1):
            k = random.randint(1, len(base_actions))
            acts = sorted(random.sample(base_actions, k=k))
            if random.random() < 0.5:
                res = [c["db_any_prefix"] + "*"]
            else:
                db_name = random.choice(["appdb", "testdb", "proddb"]) + f"{random.randint(1,99):02d}"
                res = [f"{c['db_any_prefix']}{db_name}"]
            statements.append(
                stmt(
                    sid=f"S{i}",
                    effect="Allow",
                    actions=acts,
                    resources=res,
                    principals=[c["user_alice"]],
                )
            )
        policies = [res_policy(statements)]

        baseline = [
            baseline_req(c["user_alice"], "rds:DescribeDBInstances", c["db_good"]),
        ]

        props = {
            "p1": allow_env(c["read_actions"], [c["db_any_prefix"]]),
            "p2": forbid_slice(c["write_actions"], [c["db_prod_prefix"]]),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/rds/statements_{n:03d}.json"
        out.append((rel, exp))

    return out


def gen_rds_perf_wildcards(count: int = 100) -> List[Tuple[str, Dict[str, Any]]]:
    c = _base_rds_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    patterns: List[List[str]] = [
        ["rds:DescribeDBInstances"],
        ["rds:DescribeDBInstances", "rds:ModifyDBInstance"],
        ["rds:Describe*"],
        ["rds:Describe*", "rds:ModifyDBInstance"],
        # Include baseline action explicitly so datasets remain repairable
        # under a shrink-only repair model.
        ["rds:DescribeDBInstances", "rds:*DBInstance"],
        ["rds:*"],
    ]
    num_levels = len(patterns)

    for i in range(1, count + 1):
        idx = (i * num_levels - 1) // count
        actions = patterns[idx]
        filename = f"wildcards_{i:03d}.json"

        statements = [
            stmt(
                sid="S1",
                effect="Allow",
                actions=actions,
                resources=[c["db_any_prefix"] + "*"],
                principals=[c["user_alice"]],
            )
        ]
        policies = [res_policy(statements)]

        baseline = [
            baseline_req(c["user_alice"], "rds:DescribeDBInstances", c["db_good"]),
        ]

        props = {
            "p1": allow_env(c["read_actions"], [c["db_any_prefix"]]),
            "p2": forbid_slice(c["write_actions"], [c["db_prod_prefix"]]),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/rds/{filename}"
        out.append((rel, exp))

    return out


def gen_rds_perf_universe(sizes: Iterable[int]) -> List[Tuple[str, Dict[str, Any]]]:
    c = _base_rds_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    for n in sizes:
        statements = [
            stmt(
                sid="S1",
                effect="Allow",
                actions=["rds:DescribeDBInstances", "rds:ModifyDBInstance"],
                resources=[c["db_any_prefix"] + "*"],
                principals=[c["user_alice"]],
            )
        ]
        policies = [res_policy(statements)]

        baseline = [
            baseline_req(
                c["user_alice"],
                "rds:DescribeDBInstances",
                f"{c['db_any_prefix']}appdb{i:02d}",
            )
            for i in range(1, n + 1)
        ]

        props = {
            "p1": allow_env(c["read_actions"], [c["db_any_prefix"]]),
            "p2": forbid_slice(c["write_actions"], [c["db_prod_prefix"]]),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/rds/universe_{n:04d}.json"
        out.append((rel, exp))

    return out


def main() -> None:
    PERF_RDS_DIR.mkdir(parents=True, exist_ok=True)

    cases: List[Tuple[str, Dict[str, Any]]] = []

    cases += gen_rds_perf_statements(levels=range(1, 101))
    cases += gen_rds_perf_wildcards(count=100)
    cases += gen_rds_perf_universe(sizes=[10 * i for i in range(1, 101)])

    for rel, obj in cases:
        path = EXP_DIR / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    print(f"Generated {len(cases)} RDS perf experiments under {PERF_RDS_DIR}")


if __name__ == "__main__":
    main()