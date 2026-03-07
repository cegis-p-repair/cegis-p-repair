#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate EC2-focused performance experiment JSONs for PolicyRepair.

We vary three dimensions (each in its own case family):
  1) Number of statements (with fixed universe size and no wildcards).
  2) Wildcard breadth (varying action patterns, small fixed universe).
  3) Universe size (increasing number of resources via baseline, fixed policy).

Output layout (relative to repo root):
  experiments/perf/ec2/statements_XXX.json
  experiments/perf/ec2/wildcards_XXX.json
  experiments/perf/ec2/universe_XXX.json
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
PERF_EC2_DIR = EXP_DIR / "perf" / "ec2"


def _base_ec2_constants() -> Dict[str, Any]:
    acct = "111111111111"
    region = "us-east-1"
    user_alice = f"arn:aws:iam::{acct}:user/alice"
    inst_any_prefix = f"arn:aws:ec2:{region}:{acct}:instance/"
    inst_good = f"{inst_any_prefix}i-app0001"
    inst_prod_prefix = f"{inst_any_prefix}i-prod"

    read_actions = ["ec2:DescribeInstances", "ec2:DescribeTags"]
    write_actions = [
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances",
        "ec2:RunInstances",
    ]

    return {
        "acct": acct,
        "region": region,
        "user_alice": user_alice,
        "inst_any_prefix": inst_any_prefix,
        "inst_good": inst_good,
        "inst_prod_prefix": inst_prod_prefix,
        "read_actions": read_actions,
        "write_actions": write_actions,
    }


def gen_ec2_perf_statements(levels: Iterable[int]) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Vary the total number of statements while keeping:
      - principals/actions/resources sets essentially constant,
      - no wildcards on actions (only on resources).
    """
    c = _base_ec2_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    base_actions = [
        "ec2:DescribeInstances",
        "ec2:DescribeTags",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances",
        "ec2:RunInstances",
    ]

    for n in levels:
        random.seed(1337 + int(n))  # per-level deterministic randomness

        statements: List[Dict[str, Any]] = []

        # Core broad statement ensuring both baseline coverage and a violation.
        core_actions = ["ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances"]
        statements.append(
            stmt(
                sid="S1",
                effect="Allow",
                actions=core_actions,
                resources=[c["inst_any_prefix"] + "*"],
                principals=[c["user_alice"]],
            )
        )

        # Additional (n-1) random statements with varied action subsets / resources.
        for i in range(2, n + 1):
            k = random.randint(1, len(base_actions))
            acts = sorted(random.sample(base_actions, k=k))
            # Either full prefix or a specific instance ARN.
            if random.random() < 0.5:
                res = [c["inst_any_prefix"] + "*"]
            else:
                inst_suffix = random.choice(["i-app", "i-prod", "i-test"])
                inst_id = f"{inst_suffix}{random.randint(0, 9999):04d}"
                res = [f"{c['inst_any_prefix']}{inst_id}"]
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
            baseline_req(
                c["user_alice"],
                "ec2:DescribeInstances",
                c["inst_good"],
            )
        ]

        props = {
            "p1": allow_env(c["read_actions"], [c["inst_any_prefix"]]),
            "p2": forbid_slice(c["write_actions"], [c["inst_prod_prefix"]]),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/ec2/statements_{n:03d}.json"
        out.append((rel, exp))

    return out


def gen_ec2_perf_wildcards(count: int = 100) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Vary wildcard breadth in action space for a single statement.
    We use the EC2 action catalog from policy_repair_z3_multi_io.py and
    build several levels from no wildcard to full service wildcard.
    """
    c = _base_ec2_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    inst_any_prefix = c["inst_any_prefix"]

    # Patterns roughly ordered from narrowest to widest wildcard breadth.
    patterns: List[List[str]] = [
        ["ec2:DescribeInstances"],  # 1 concrete read
        ["ec2:DescribeInstances", "ec2:DescribeTags"],  # 2 concrete reads
        ["ec2:Describe*"],  # read-only wildcard
        ["ec2:Describe*", "ec2:StartInstances"],  # read wildcard + 1 write
        ["ec2:Describe*", "ec2:StartInstances", "ec2:StopInstances"],
        ["ec2:*Instances"],  # suffix wildcard
        ["ec2:*Instances", "ec2:RunInstances"],
        ["ec2:*"],  # full service wildcard
    ]

    num_levels = len(patterns)

    for i in range(1, count + 1):
        # Map i in [1, count] to a pattern index in [0, num_levels-1],
        # so later cases tend to have broader wildcards.
        idx = (i * num_levels - 1) // count
        actions = patterns[idx]
        filename = f"wildcards_{i:03d}.json"

        statements = [
            stmt(
                sid="S1",
                effect="Allow",
                actions=actions,
                resources=[inst_any_prefix + "*"],
                principals=[c["user_alice"]],
            )
        ]
        policies = [res_policy(statements)]

        baseline = [
            baseline_req(
                c["user_alice"],
                "ec2:DescribeInstances",
                c["inst_good"],
            )
        ]

        props = {
            "p1": allow_env(c["read_actions"], [inst_any_prefix]),
            "p2": forbid_slice(c["write_actions"], [c["inst_prod_prefix"]]),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/ec2/{filename}"
        out.append((rel, exp))

    return out


def gen_ec2_perf_universe(sizes: Iterable[int]) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Vary the universe size by increasing the number of distinct
    resources in the baseline (and thus in the enumerated resource set).
    The policy itself is fixed and over-permissive, so repair still does work.
    """
    c = _base_ec2_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    inst_any_prefix = c["inst_any_prefix"]

    for n in sizes:
        # One over-broad resource policy (allows read + start on all instances).
        statements = [
            stmt(
                sid="S1",
                effect="Allow",
                actions=["ec2:DescribeInstances", "ec2:StartInstances"],
                resources=[inst_any_prefix + "*"],
                principals=[c["user_alice"]],
            )
        ]
        policies = [res_policy(statements)]

        # Baseline with n distinct app instances (same principal + action).
        baseline = [
            baseline_req(
                c["user_alice"],
                "ec2:DescribeInstances",
                f"{inst_any_prefix}i-app{i:04d}",
            )
            for i in range(1, n + 1)
        ]

        props = {
            "p1": allow_env(c["read_actions"], [inst_any_prefix]),
            "p2": forbid_slice(c["write_actions"], [c["inst_prod_prefix"]]),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/ec2/universe_{n:04d}.json"
        out.append((rel, exp))

    return out


def main() -> None:
    PERF_EC2_DIR.mkdir(parents=True, exist_ok=True)

    cases: List[Tuple[str, Dict[str, Any]]] = []

    # 1) Increasing number of statements: 100 cases (1..100 statements).
    cases += gen_ec2_perf_statements(levels=range(1, 101))

    # 2) Increasing wildcard breadth: 100 cases.
    cases += gen_ec2_perf_wildcards(count=100)

    # 3) Increasing universe size via baseline resources: 100 cases.
    #    Universe grows from 10 to 1000 resources in steps of 10.
    cases += gen_ec2_perf_universe(sizes=[10 * i for i in range(1, 101)])

    for rel, obj in cases:
        path = EXP_DIR / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    print(f"Generated {len(cases)} EC2 perf experiments under {PERF_EC2_DIR}")


if __name__ == "__main__":
    main()