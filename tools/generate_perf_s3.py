#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate S3-focused performance experiment JSONs for PolicyRepair.

We vary three dimensions (each in its own case family):
  1) Number of statements (with fixed universe size and no action wildcards).
  2) Wildcard breadth (varying action patterns, small fixed universe).
  3) Universe size (increasing number of S3 objects via baseline, fixed policy).

Output layout (relative to repo root):
  experiments/perf/s3/statements_XXX.json
  experiments/perf/s3/wildcards_XXX.json
  experiments/perf/s3/universe_XXXX.json
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
PERF_S3_DIR = EXP_DIR / "perf" / "s3"


def _base_s3_constants() -> Dict[str, Any]:
    acct = "111111111111"
    bucket = "acme-perf"
    user_alice = f"arn:aws:iam::{acct}:user/alice"
    pref_logs = f"arn:aws:s3:::{bucket}/logs/"
    pref_reports = f"arn:aws:s3:::{bucket}/reports/"
    pref_secret = f"arn:aws:s3:::{bucket}/secret"

    read_actions = [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListBucket",
        "s3:GetBucketLocation",
    ]
    write_actions = [
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload",
        "s3:PutObjectTagging",
    ]

    return {
        "acct": acct,
        "bucket": bucket,
        "user_alice": user_alice,
        "pref_logs": pref_logs,
        "pref_reports": pref_reports,
        "pref_secret": pref_secret,
        "read_actions": read_actions,
        "write_actions": write_actions,
    }


def gen_s3_perf_statements(levels: Iterable[int]) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Vary the total number of statements while keeping:
      - principals/actions/resources sets essentially constant,
      - no wildcards on actions (only on resources).
    """
    c = _base_s3_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    bucket_arn_prefix = f"arn:aws:s3:::{c['bucket']}/"

    for n in levels:
        random.seed(2333 + int(n))

        statements: List[Dict[str, Any]] = []

        # Core broad statement.
        core_actions = ["s3:GetObject", "s3:PutObject"]
        statements.append(
            stmt(
                sid="S1",
                effect="Allow",
                actions=core_actions,
                resources=[bucket_arn_prefix + "*"],
                principals=[c["user_alice"]],
            )
        )

        base_actions = c["read_actions"] + c["write_actions"]

        for i in range(2, n + 1):
            k = random.randint(1, len(base_actions))
            acts = sorted(random.sample(base_actions, k=k))
            if random.random() < 0.5:
                res = [bucket_arn_prefix + "*"]
            else:
                sub = random.choice(["logs", "reports", "tmp"])
                res = [f"arn:aws:s3:::{c['bucket']}/{sub}/"]
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
                "s3:GetObject",
                f"{c['pref_logs']}obj0001.log",
                {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"},
            ),
            baseline_req(
                c["user_alice"],
                "s3:GetObject",
                f"{c['pref_reports']}r1.txt",
                {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"},
            ),
        ]

        props = {
            "p1": allow_env(c["read_actions"], [c["pref_logs"], c["pref_reports"]]),
            "p2": forbid_slice(
                c["write_actions"],
                [c["pref_secret"], f"arn:aws:s3:::{c['bucket']}/backups"],
            ),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/s3/statements_{n:03d}.json"
        out.append((rel, exp))

    return out


def gen_s3_perf_wildcards(count: int = 100) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Vary wildcard breadth in action space for a single statement.
    Patterns range from concrete GetObject to full s3:*.
    """
    c = _base_s3_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    bucket_arn_prefix = f"arn:aws:s3:::{c['bucket']}/"

    patterns: List[List[str]] = [
        ["s3:GetObject"],
        ["s3:GetObject", "s3:PutObject"],
        ["s3:Get*"],
        ["s3:Get*", "s3:PutObject"],
        ["s3:Get*", "s3:Put*"],
        ["s3:*"],
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
                resources=[bucket_arn_prefix + "*"],
                principals=[c["user_alice"]],
            )
        ]
        policies = [res_policy(statements)]

        baseline = [
            baseline_req(
                c["user_alice"],
                "s3:GetObject",
                f"{c['pref_logs']}obj0001.log",
                {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"},
            )
        ]

        props = {
            "p1": allow_env(c["read_actions"], [c["pref_logs"], c["pref_reports"]]),
            "p2": forbid_slice(
                c["write_actions"],
                [c["pref_secret"], f"arn:aws:s3:::{c['bucket']}/backups"],
            ),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/s3/{filename}"
        out.append((rel, exp))

    return out


def gen_s3_perf_universe(sizes: Iterable[int]) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Vary the universe size by increasing the number of distinct S3 objects
    in the baseline (and thus in the enumerated resource set).
    """
    c = _base_s3_constants()
    out: List[Tuple[str, Dict[str, Any]]] = []

    bucket_arn_prefix = f"arn:aws:s3:::{c['bucket']}/"

    for n in sizes:
        statements = [
            stmt(
                sid="S1",
                effect="Allow",
                actions=["s3:GetObject", "s3:PutObject"],
                resources=[bucket_arn_prefix + "*"],
                principals=[c["user_alice"]],
            )
        ]
        policies = [res_policy(statements)]

        baseline = [
            baseline_req(
                c["user_alice"],
                "s3:GetObject",
                f"{c['pref_logs']}obj{i:04d}.log",
                {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"},
            )
            for i in range(1, n + 1)
        ]

        props = {
            "p1": allow_env(c["read_actions"], [c["pref_logs"], c["pref_reports"]]),
            "p2": forbid_slice(
                c["write_actions"],
                [c["pref_secret"], f"arn:aws:s3:::{c['bucket']}/backups"],
            ),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }

        rel = f"perf/s3/universe_{n:04d}.json"
        out.append((rel, exp))

    return out


def main() -> None:
    PERF_S3_DIR.mkdir(parents=True, exist_ok=True)

    cases: List[Tuple[str, Dict[str, Any]]] = []

    # 1) Increasing number of statements: 100 cases (1..100).
    cases += gen_s3_perf_statements(levels=range(1, 101))

    # 2) Increasing wildcard breadth: 100 cases.
    cases += gen_s3_perf_wildcards(count=100)

    # 3) Increasing universe size via baseline resources: 100 cases (10..1000).
    cases += gen_s3_perf_universe(sizes=[10 * i for i in range(1, 101)])

    for rel, obj in cases:
        path = EXP_DIR / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    print(f"Generated {len(cases)} S3 perf experiments under {PERF_S3_DIR}")


if __name__ == "__main__":
    main()