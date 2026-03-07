#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate experiment JSONs for S3/EC2/RDS/Lambda.
Each service gets 24 cases with variations across policy kind,
action breadth, resource breadth, and conditions.

Output layout:
  experiments/
    s3/case_XXX.json
    ec2/case_XXX.json
    rds/case_XXX.json
    lambda/case_XXX.json
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, List, Any


ROOT = Path(__file__).resolve().parents[1]
EXP_DIR = ROOT / "experiments"


def allow_env(actions, prefixes):
    return {"actions": list(sorted(set(actions))), "resource_prefixes": list(prefixes)}


def forbid_slice(actions, prefixes):
    return {"actions": list(sorted(set(actions))), "resource_prefixes": list(prefixes)}


def ident_policy(attached_principals: List[str], statements: List[Dict[str, Any]]):
    return {"kind": "identity", "attached_principals": attached_principals, "statements": statements}


def res_policy(statements: List[Dict[str, Any]]):
    return {"kind": "resource", "statements": statements}


def stmt(sid, effect, actions, resources, principals=None, conditions=None):
    return {
        "sid": sid,
        "effect": effect,
        "principals": principals or [],
        "actions": actions,
        "resources": resources,
        "conditions": conditions or {},
    }


def baseline_req(principal, action, resource, gamma=None):
    return {"principal": principal, "action": action, "resource": resource, "gamma": gamma or {}}


def gen_s3_cases(n=48):
    out = []
    acct = "111111111111"
    user_alice = f"arn:aws:iam::{acct}:user/alice"
    user_bob = f"arn:aws:iam::{acct}:user/bob"
    read = ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:GetBucketLocation"]
    write = ["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:PutObjectTagging"]
    for i in range(1, n + 1):
        bucket = f"acme-b{i:02d}"
        pref_logs = f"arn:aws:s3:::{bucket}/logs/"
        pref_reports = f"arn:aws:s3:::{bucket}/reports/"
        pref_secret = f"arn:aws:s3:::{bucket}/secret"

        policies = []
        # alternate between identity/resource policies
        if i % 2 == 0:
            # identity policy: too broad action or resource
            if i % 4 == 0:
                # Over-broad actions (s3:*) on bucket/*
                policies.append(ident_policy(
                    [user_alice],
                    [stmt("S1", "Allow", ["s3:*"], [f"arn:aws:s3:::{bucket}/*"])],
                ))
            else:
                # Over-broad resources for Get* (should narrow to logs/)
                policies.append(ident_policy(
                    [user_alice],
                    [stmt("S1", "Allow", ["s3:Get*"], [f"arn:aws:s3:::{bucket}/*"])],
                ))
        else:
            # resource policy: principals are wide; missing org condition
            principals = ["*"] if (i % 3 == 1) else [user_alice, user_bob]
            actions = ["s3:GetObject"] if (i % 3 == 1) else ["s3:GetObject", "s3:PutObject"]
            conditions = {} if (i % 3 == 1) else {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"}
            policies.append(res_policy([
                stmt("S1", "Allow", actions, [f"arn:aws:s3:::{bucket}/*"], principals=principals, conditions=conditions)
            ]))

        baseline = [
            baseline_req(user_alice, "s3:GetObject", f"{pref_logs}app.log", {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"}),
            baseline_req(user_alice, "s3:GetObject", f"{pref_reports}r1.txt", {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"}),
        ]

        props = {
            "p1": allow_env(read, [pref_logs, pref_reports]),
            "p2": forbid_slice(write, [pref_secret, f"arn:aws:s3:::{bucket}/backups"]),
        }

        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }
        out.append((f"s3/case_{i:02d}.json", exp))
    return out


def gen_ec2_cases(n=48):
    out = []
    acct = "111111111111"
    region = "us-east-1"
    user_alice = f"arn:aws:iam::{acct}:user/alice"
    read = ["ec2:DescribeInstances", "ec2:DescribeTags"]
    write = ["ec2:StartInstances", "ec2:StopInstances", "ec2:TerminateInstances", "ec2:RunInstances"]
    for i in range(1, n + 1):
        inst_good = f"arn:aws:ec2:{region}:{acct}:instance/i-app{i:04d}"
        inst_prod = f"arn:aws:ec2:{region}:{acct}:instance/i-prod{i:04d}"
        inst_any_prefix = f"arn:aws:ec2:{region}:{acct}:instance/"

        policies = []
        if i % 2 == 0:
            # identity, too-broad actions
            policies.append(ident_policy(
                [user_alice],
                [stmt("S1", "Allow", ["ec2:*" if (i % 4 == 0) else "ec2:StartInstances", "ec2:DescribeInstances"], [inst_any_prefix + "*"])]
            ))
        else:
            # resource, too-broad resources
            principals = [user_alice]
            actions = ["ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances"]
            policies.append(res_policy([
                stmt("S1", "Allow", actions, [inst_any_prefix + "*"], principals=principals)
            ]))

        baseline = [
            baseline_req(user_alice, "ec2:DescribeInstances", inst_good),
        ]
        props = {
            "p1": allow_env(read, [inst_any_prefix]),
            "p2": forbid_slice(write, [inst_prod[: inst_prod.rfind("/")+1] + "i-prod"])  # forbid instances with prefix i-prod
        }
        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }
        out.append((f"ec2/case_{i:02d}.json", exp))
    return out


def gen_rds_cases(n=48):
    out = []
    acct = "111111111111"
    region = "us-east-1"
    user_alice = f"arn:aws:iam::{acct}:user/alice"
    read = ["rds:DescribeDBInstances", "rds:ListTagsForResource"]
    write = ["rds:CreateDBInstance", "rds:DeleteDBInstance", "rds:ModifyDBInstance"]
    for i in range(1, n + 1):
        db_good = f"arn:aws:rds:{region}:{acct}:db:appdb{i:02d}"
        db_prod = f"arn:aws:rds:{region}:{acct}:db:proddb{i:02d}"
        db_any_prefix = f"arn:aws:rds:{region}:{acct}:db:"

        policies = []
        if i % 2 == 0:
            policies.append(ident_policy(
                [user_alice],
                [stmt("S1", "Allow", ["rds:*" if (i % 4 == 0) else "rds:ModifyDBInstance", "rds:DescribeDBInstances"], [db_any_prefix + "*"])]
            ))
        else:
            principals = [user_alice]
            actions = ["rds:DescribeDBInstances", "rds:ModifyDBInstance"]
            policies.append(res_policy([
                stmt("S1", "Allow", actions, [db_any_prefix + "*"], principals=principals)
            ]))

        baseline = [
            baseline_req(user_alice, "rds:DescribeDBInstances", db_good),
        ]
        props = {
            "p1": allow_env(read, [db_any_prefix]),
            "p2": forbid_slice(write, [db_prod[: db_prod.rfind(":") + 1] + "proddb"])  # forbid db name prefix proddb
        }
        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }
        out.append((f"rds/case_{i:02d}.json", exp))
    return out


def gen_lambda_cases(n=48):
    out = []
    acct = "111111111111"
    region = "us-east-1"
    user_alice = f"arn:aws:iam::{acct}:user/alice"
    read = ["lambda:GetFunction", "lambda:ListFunctions"]
    write = ["lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:DeleteFunction", "lambda:PublishVersion", "lambda:InvokeFunction"]
    for i in range(1, n + 1):
        fn_good = f"arn:aws:lambda:{region}:{acct}:function:app-func-{i:02d}"
        fn_prod = f"arn:aws:lambda:{region}:{acct}:function:prod-func-{i:02d}"
        fn_any_prefix = f"arn:aws:lambda:{region}:{acct}:function:"

        policies = []
        if i % 2 == 0:
            policies.append(ident_policy(
                [user_alice],
                [stmt("S1", "Allow", ["lambda:*" if (i % 4 == 0) else "lambda:InvokeFunction", "lambda:GetFunction"], [fn_any_prefix + "*"])]
            ))
        else:
            principals = [user_alice]
            actions = ["lambda:GetFunction", "lambda:InvokeFunction"]
            # Sometimes missing org condition to trigger R3
            cond = {} if (i % 3 == 1) else {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"}
            policies.append(res_policy([
                stmt("S1", "Allow", actions, [fn_any_prefix + "*"], principals=principals, conditions=cond)
            ]))

        baseline = [
            baseline_req(user_alice, "lambda:GetFunction", fn_good, {"aws:PrincipalOrgID": "o-ABCDEFGHIJK"}),
        ]
        props = {
            "p1": allow_env(read, [fn_any_prefix]),
            "p2": forbid_slice(write, [fn_prod[: fn_prod.rfind(":") + 1] + "prod-"]),
        }
        exp = {
            "policies": policies,
            "properties": props,
            "baseline": baseline,
            "verbose": True,
            "max_iters": 10,
        }
        out.append((f"lambda/case_{i:02d}.json", exp))
    return out


def main():
    (EXP_DIR / "s3").mkdir(parents=True, exist_ok=True)
    (EXP_DIR / "ec2").mkdir(parents=True, exist_ok=True)
    (EXP_DIR / "rds").mkdir(parents=True, exist_ok=True)
    (EXP_DIR / "lambda").mkdir(parents=True, exist_ok=True)

    cases = []
    cases += gen_s3_cases()
    cases += gen_ec2_cases()
    cases += gen_rds_cases()
    cases += gen_lambda_cases()

    for rel, obj in cases:
        path = EXP_DIR / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    print(f"Generated {len(cases)} experiments under {EXP_DIR}")


if __name__ == "__main__":
    main()
