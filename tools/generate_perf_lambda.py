#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate Lambda-focused performance experiment JSONs for PolicyRepair.

Dimensions:
  1) Number of statements.
  2) Wildcard breadth in Lambda actions.
  3) Universe size (number of Lambda function ARNs in baseline).

Output layout:
  experiments/perf/lambda/statements_XXX.json
  experiments/perf/lambda/wildcards_XXX.json
  experiments/perf/lambda/universe_XXXX.json
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
PERF_LAMBDA_DIR = EXP_DIR / "perf" / "lambda"


def _base_lambda_constants() -> Dict[str, Any]:
    acct = "111111111111"
    region = "us-east-1"
    user_alice = f"arn:aws:iam::{acct}:user/alice"
    fn_any_prefix = f"arn:aws:lambda:{region}:{acct}:function:"
    fn_good = f"{fn_any_prefix}app-func-01"
    fn_prod_prefix = f"{fn_any_prefix}prod-"

    read_actions = ["lambda:GetFunction", "lambda:ListFunctions"]
    write_actions = [
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "lambda:DeleteFunction",
        "lambda:PublishVersion",
        "lambda:InvokeFunction",
    ]

    return {
        "acct": acct,
        "region": region,
        "user_alice": user_alice,
        "fn_any_prefix": fn_any_prefix,
        "fn_good": fn_good,
        "fn_prod_prefix": fn_prod_prefix,
        "read_actions": read_actions,
        "write_actions": write_actions,
    }


def gen_lambda_perf_statements(levels: Iterable[int]) -> List[Tuple[str, Dict[str, Any]]]:
    c = _base_lambda_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    for n in levels:
        random.seed(4555 + int(n))

        statements: List[Dict[str, Any]] = []

        # Core broad statement.
        core_actions = ["lambda:GetFunction", "lambda:InvokeFunction"]
        statements.append(
            stmt(
                sid="S1",
                effect="Allow",
                actions=core_actions,
                resources=[c["fn_any_prefix"] + "*"],
                principals=[c["user_alice"]],
            )
        )

        base_actions = c["read_actions"] + c["write_actions"]

        for i in range(2, n + 1):
            k = random.randint(1, len(base_actions))
            acts = sorted(random.sample(base_actions, k=k))
            if random.random() < 0.5:
                res = [c["fn_any_prefix"] + "*"]
            else:
                name = random.choice(["app-func", "dev-func", "prod-func"]) + f"-{random.randint(1,99):02d}"
                res = [f"{c['fn_any_prefix']}{name}"]
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
                "lambda:GetFunction",
                c["fn_good"],
                {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"},
            ),
        ]

        props = {
            "p1": allow_env(c["read_actions"], [c["fn_any_prefix"]]),
            "p2": forbid_slice(c["write_actions"], [c["fn_prod_prefix"]]),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/lambda/statements_{n:03d}.json"
        out.append((rel, exp))

    return out


def gen_lambda_perf_wildcards(count: int = 100) -> List[Tuple[str, Dict[str, Any]]]:
    c = _base_lambda_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    patterns: List[List[str]] = [
        ["lambda:GetFunction"],
        ["lambda:GetFunction", "lambda:InvokeFunction"],
        ["lambda:Get*"],
        ["lambda:Get*", "lambda:InvokeFunction"],
        ["lambda:*Function"],
        ["lambda:*"],
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
                resources=[c["fn_any_prefix"] + "*"],
                principals=[c["user_alice"]],
            )
        ]
        policies = [res_policy(statements)]

        baseline = [
            baseline_req(
                c["user_alice"],
                "lambda:GetFunction",
                c["fn_good"],
                {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"},
            ),
        ]

        props = {
            "p1": allow_env(c["read_actions"], [c["fn_any_prefix"]]),
            "p2": forbid_slice(c["write_actions"], [c["fn_prod_prefix"]]),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/lambda/{filename}"
        out.append((rel, exp))

    return out


def gen_lambda_perf_universe(sizes: Iterable[int]) -> List[Tuple[str, Dict[str, Any]]]:
    c = _base_lambda_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    for n in sizes:
        statements = [
            stmt(
                sid="S1",
                effect="Allow",
                actions=["lambda:GetFunction", "lambda:InvokeFunction"],
                resources=[c["fn_any_prefix"] + "*"],
                principals=[c["user_alice"]],
            )
        ]
        policies = [res_policy(statements)]

        baseline = [
            baseline_req(
                c["user_alice"],
                "lambda:GetFunction",
                f"{c['fn_any_prefix']}app-func-{i:02d}",
                {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"},
            )
            for i in range(1, n + 1)
        ]

        props = {
            "p1": allow_env(c["read_actions"], [c["fn_any_prefix"]]),
            "p2": forbid_slice(c["write_actions"], [c["fn_prod_prefix"]]),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/lambda/universe_{n:04d}.json"
        out.append((rel, exp))

    return out


def main() -> None:
    PERF_LAMBDA_DIR.mkdir(parents=True, exist_ok=True)

    cases: List[Tuple[str, Dict[str, Any]]] = []

    cases += gen_lambda_perf_statements(levels=range(1, 101))
    cases += gen_lambda_perf_wildcards(count=100)
    cases += gen_lambda_perf_universe(sizes=[10 * i for i in range(1, 101)])

    for rel, obj in cases:
        path = EXP_DIR / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    print(f"Generated {len(cases)} Lambda perf experiments under {PERF_LAMBDA_DIR}")


if __name__ == "__main__":
    main()