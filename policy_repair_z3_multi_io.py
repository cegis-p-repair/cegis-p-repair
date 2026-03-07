#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import re
import copy
import json
import argparse
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set, Any

# z3 solver (pip install z3-solver)
try:
    from z3 import Bool, Optimize, Sum, If, IntVal, Or, And, Not, sat
except Exception as e:
    print("WARNING: z3-solver not available at runtime. The script can still be read.")
    Bool = Optimize = Sum = If = IntVal = Or = And = Not = lambda *args, **kwargs: None  # type: ignore
    sat = None  # type: ignore


DEFAULT_WEIGHTS = {"R2": 1, "R3": 1, "R1": 2, "R4": 4}


# -------------------------------
# Data Model
# -------------------------------

@dataclass
class Statement:
    """Simplified IAM statement; for resource-based policies, principals live here."""
    sid: str
    effect: str                 # "Allow" or "Deny"
    principals: List[str]       # resource-based uses this; identity-based ignores this field
    actions: List[str]
    resources: List[str]
    conditions: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Policy:
    """Policy container with kind + optional attached principals for identity-based policies."""
    kind: str                                   # "identity" or "resource"
    statements: List[Statement]
    attached_principals: List[str] = field(default_factory=list)  # only for kind="identity"

@dataclass
class Request:
    """Concrete request being checked."""
    principal: str
    action: str
    resource: str
    gamma: Dict[str, Any]


# -------------------------------
# Merge Helpers (Optional Preprocessing)
# -------------------------------

def merge_statements_simple(stmts: List[Statement]) -> List[Statement]:
    """
    Merge a list of statements into a single statement when safe.

    Safety criteria (for this demo):
      - all statements share the same effect ("Allow" or "Deny");
      - all statements have identical conditions.

    The merged statement keeps union of principals, actions and resources.
    If criteria are not met, a ValueError is raised.
    """
    if not stmts:
        return []
    effects = {s.effect for s in stmts}
    if len(effects) > 1:
        raise ValueError("Merge conflict: mixed Allow/Deny statements in one policy")
    cond_keys = {tuple(sorted(s.conditions.items())) for s in stmts}
    if len(cond_keys) > 1:
        raise ValueError("Merge conflict: heterogeneous conditions in one policy")

    effect = next(iter(effects))
    principals: Set[str] = set()
    actions: Set[str] = set()
    resources: Set[str] = set()
    for s in stmts:
        principals.update(s.principals)
        actions.update(s.actions)
        resources.update(s.resources)
    base_cond_items = sorted(stmts[0].conditions.items())
    conditions = {k: v for k, v in base_cond_items}

    merged = Statement(
        sid=stmts[0].sid or "S",
        effect=effect,
        principals=sorted(principals),
        actions=sorted(actions),
        resources=sorted(resources),
        conditions=conditions,
    )
    return [merged]


def merge_policies_for_repair(policies: List[Policy]) -> List[Policy]:
    """
    Attempt to merge all statements inside each policy into a single statement.
    If a policy does not satisfy the safety criteria, a ValueError is raised
    so that the caller can refuse to repair that input.
    """
    merged_policies: List[Policy] = []
    for idx, pol in enumerate(policies):
        if len(pol.statements) <= 1:
            merged_policies.append(copy.deepcopy(pol))
            continue
        try:
            new_stmts = merge_statements_simple(pol.statements)
        except ValueError as e:
            raise ValueError(f"Merge conflict in policy[{idx}]: {e}") from e
        merged_policies.append(
            Policy(
                kind=pol.kind,
                statements=new_stmts,
                attached_principals=list(pol.attached_principals),
            )
        )
    return merged_policies


# -------------------------------
# Action Catalogs (Toy) and Helpers
# -------------------------------

# Per-service read/write action samples (not exhaustive)
S3_READ = {"s3:GetObject", "s3:ListBucket", "s3:GetObjectVersion", "s3:GetBucketLocation"}
S3_WRITE = {"s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:PutObjectTagging"}
EC2_READ = {"ec2:DescribeInstances", "ec2:DescribeTags"}
EC2_WRITE = {"ec2:StartInstances", "ec2:StopInstances", "ec2:TerminateInstances", "ec2:RunInstances"}
RDS_READ = {"rds:DescribeDBInstances", "rds:ListTagsForResource"}
RDS_WRITE = {"rds:CreateDBInstance", "rds:DeleteDBInstance", "rds:ModifyDBInstance"}
LAMBDA_READ = {"lambda:GetFunction", "lambda:ListFunctions"}
LAMBDA_WRITE = {"lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:DeleteFunction", "lambda:PublishVersion", "lambda:InvokeFunction"}

ACTION_CATALOGS: Dict[str, Set[str]] = {
    "s3": S3_READ | S3_WRITE,
    "ec2": EC2_READ | EC2_WRITE,
    "rds": RDS_READ | RDS_WRITE,
    "lambda": LAMBDA_READ | LAMBDA_WRITE,
}

READ_ONLY_SETS: Dict[str, Set[str]] = {
    "s3": S3_READ,
    "ec2": EC2_READ,
    "rds": RDS_READ,
    "lambda": LAMBDA_READ,
}

def action_service(action: str) -> Optional[str]:
    """Return service prefix of an action like 'ec2:StartInstances' -> 'ec2'."""
    m = re.match(r"^([^:]+):", action)
    return m.group(1).lower() if m else None

def expand_action_wildcards(actions: List[str]) -> Set[str]:
    """
    Expand wildcards per service catalog: 'ec2:*', 'lambda:Get*', 'ec2:*Instances' etc.
    Unknown services or patterns without wildcards are kept literal.
    """
    expanded: Set[str] = set()
    for a in actions:
        m = re.match(r"^([^:]+):(.*)$", a)
        if not m:
            expanded.add(a)
            continue
        svc, tail = m.group(1).lower(), m.group(2)
        catalog = ACTION_CATALOGS.get(svc, set())

        # No catalog for this service, or no wildcard characters: keep literal.
        if not catalog or ("*" not in tail and "?" not in tail):
            expanded.add(a)
            continue

        # Simple '*' covers the whole catalog.
        if tail == "*":
            expanded |= set(catalog)
            continue

        # General glob over the catalog, e.g., Describe*, *Instances, *.
        pattern = f"{svc}:{tail}"
        matched = {aa for aa in catalog if matches_glob(aa, pattern)}
        if matched:
            expanded |= matched
        else:
            # Fallback: keep original literal if nothing matched.
            expanded.add(a)
    return expanded

def glob_to_regex(glob: str) -> str:
    """Convert simple glob (* and ?) to regex; escape other regex chars."""
    esc = re.escape(glob)
    esc = esc.replace(r"\*", ".*").replace(r"\?", ".")
    return "^" + esc + "$"

def matches_glob(text: str, glob: str) -> bool:
    """Glob-style matching used for principals/resources."""
    return re.match(glob_to_regex(glob), text) is not None


# -------------------------------
# Resource Parsers / Narrowers
# -------------------------------

def s3_parse_arn(arn: str) -> Tuple[str, str]:
    """Parse S3 ARN to (bucket, key). arn:aws:s3:::bucket[/key...]"""
    m = re.match(r"^arn:aws:s3:::(?P<bucket>[^/]+)(?:/(?P<key>.*))?$", arn)
    if not m:
        return ("", "")
    return (m.group("bucket"), m.group("key") or "")

def key_common_prefix_excluding(keys_good: List[str], bad_key: str) -> Optional[str]:
    """Return directory-like prefix p ending with '/' that covers all good keys but excludes bad_key."""
    if not keys_good:
        return None
    common = keys_good[0]
    for k in keys_good[1:]:
        while not k.startswith(common) and common:
            common = common[:-1]
        if not common:
            break
    candidates = set()
    for i in range(1, len(common)+1):
        if common[i-1] == '/':
            candidates.add(common[:i])
    if common.endswith('/'):
        candidates.add(common)
    for p in sorted(candidates, key=len):
        if not bad_key.startswith(p):
            return p
    return None

def generic_prefix_excluding(goods: List[str], bad: str) -> Optional[str]:
    """
    Service-agnostic prefix finder: choose the shortest prefix that covers all goods but excludes bad.
    We limit cut points to '/', ':' or the full common prefix.
    """
    if not goods:
        return None
    common = goods[0]
    for g in goods[1:]:
        while not g.startswith(common) and common:
            common = common[:-1]
        if not common:
            break
    # consider boundaries at '/', ':'
    cuts = {i for i,c in enumerate(common, start=1) if c in ["/", ":"]}
    if common:
        cuts.add(len(common))
    for i in sorted(cuts):
        pref = common[:i]
        if not bad.startswith(pref):
            return pref
    return None


# -------------------------------
# Conditions and Evaluation
# -------------------------------

def conditions_hold(conds: Dict[str, Any], gamma: Dict[str, Any]) -> bool:
    """
    Equality-only demo:
      - "aws:PrincipalOrgID", "aws:SourceVpc", tag-like keys
    """
    for k, v in conds.items():
        if k not in gamma:
            return False
        if str(gamma[k]) != str(v):
            return False
    return True

def statement_applies(policy: Policy, s: Statement, q: Request) -> bool:
    """Check if statement s is applicable to request q under policy kind semantics."""
    # Identity-based: principal must match policy.attached_principals (statement.principals ignored)
    if policy.kind == "identity":
        if policy.attached_principals and not any(matches_glob(q.principal, patt) for patt in policy.attached_principals):
            return False
    # Resource-based: principal must match statement.principals
    elif policy.kind == "resource":
        if not s.principals or not any(matches_glob(q.principal, patt) for patt in s.principals):
            return False
    else:
        return False

    # Action
    if q.action not in expand_action_wildcards(s.actions):
        return False
    # Resource
    if not any(matches_glob(q.resource, patt) for patt in s.resources):
        return False
    # Conditions
    if not conditions_hold(s.conditions, q.gamma):
        return False
    return True

def permit(policies: List[Policy], q: Request) -> bool:
    """IAM-like composition: Allow if ANY policy allows and NO policy denies (explicit deny wins)."""
    allowed = False
    denied = False
    for pol in policies:
        for s in pol.statements:
            if not statement_applies(pol, s, q):
                continue
            if s.effect == "Deny":
                denied = True
            elif s.effect == "Allow":
                allowed = True
    return allowed and (not denied)


# -------------------------------
# Properties
# -------------------------------

@dataclass
class AllowEnvelope:
    """P1: allowed region (actions × resource-prefixes)."""
    actions: Set[str]
    resource_prefixes: List[str]

    def in_envelope(self, q: Request) -> bool:
        if q.action not in self.actions:
            return False
        return any(q.resource.startswith(pref) for pref in self.resource_prefixes)

@dataclass
class ForbidSlice:
    """P2: forbidden slice (actions × resource-prefixes)."""
    actions: Set[str]
    resource_prefixes: List[str]

    def is_forbidden(self, q: Request) -> bool:
        return (q.action in self.actions) and any(q.resource.startswith(pref) for pref in self.resource_prefixes)


# -------------------------------
# Verifier (enumeration-based for demo)
# -------------------------------

@dataclass
class VerifyResult:
    """Verification outcome with an optional violating witness and its kind."""
    sat: bool
    witness: Optional[Request] = None
    kind: Optional[str] = None   # "P1", "P2", or "Baseline"

def build_universe(policies: List[Policy],
                   p1: AllowEnvelope,
                   p2: ForbidSlice,
                   baseline: List[Request]) -> Tuple[Set[str], Set[str], Set[str]]:
    """
    Small enumerative universes:
      - principals: baseline + attached_principals (identity) + literal principals in resource policies
      - actions: from policies + P1 + P2
      - resources: baseline + synthetic siblings + P1/P2 prefixes
    """
    principals = set(b.principal for b in baseline)
    for pol in policies:
        if pol.kind == "identity":
            principals |= set(pol.attached_principals)
        for s in pol.statements:
            for patt in s.principals:
                if ("*" not in patt) and ("?" not in patt):
                    principals.add(patt)

    actions = set()
    for pol in policies:
        for s in pol.statements:
            actions |= expand_action_wildcards(s.actions)
    actions |= p1.actions
    actions |= p2.actions

    resources = set(b.resource for b in baseline)

    # Synthetic siblings for S3; for others, simple name tweaks
    s3s = [r for r in list(resources) if r.startswith("arn:aws:s3:::")]
    for r in s3s:
        bucket, key = s3_parse_arn(r)
        if bucket and key:
            if key.startswith("logs/"):
                resources.add(f"arn:aws:s3:::{bucket}/secret.txt")
            else:
                resources.add(f"arn:aws:s3:::{bucket}/logs/example.txt")
    # Add P1/P2 prefixes with an example tail
    for pref in p1.resource_prefixes + p2.resource_prefixes:
        if pref.endswith('/'):
            resources.add(pref + "example")
        else:
            resources.add(pref.rstrip('/') + '/example')

    return principals, actions, resources

def verify(policies: List[Policy],
           p1: AllowEnvelope,
           p2: ForbidSlice,
           baseline: List[Request]) -> VerifyResult:
    # Baseline must pass
    for b in baseline:
        if not permit(policies, b):
            return VerifyResult(sat=False, witness=b, kind="Baseline")

    principals, actions, resources = build_universe(policies, p1, p2, baseline)

    # P2 forbidden slice must not be permitted
    for p in principals:
        for a in actions:
            for r in resources:
                q = Request(principal=p, action=a, resource=r, gamma={})
                if permit(policies, q) and p2.is_forbidden(q):
                    return VerifyResult(sat=False, witness=q, kind="P2")

    # Any permitted request must be inside P1 envelope
    for p in principals:
        for a in actions:
            for r in resources:
                q = Request(principal=p, action=a, resource=r, gamma={})
                if permit(policies, q) and (not p1.in_envelope(q)):
                    return VerifyResult(sat=False, witness=q, kind="P1")

    return VerifyResult(sat=True)


# -------------------------------
# Candidate Edits (R1/R2/R3/R4)
# -------------------------------

@dataclass(frozen=True)
class Target:
    """Reference to a specific statement inside a specific policy by index + sid."""
    policy_idx: int
    sid: str

@dataclass(frozen=True)
class Edit:
    """Atomic patch on a target statement (or NEW deny)."""
    kind: str                 # "R1", "R2", "R3", "R4"
    target: Target            # for R4/NEW, we will attach to the first covering policy by default
    payload: Tuple            # see generators
    weight: int
    group: Optional[str] = None

def cov_statements(policies: List[Policy], w: Request) -> List[Tuple[int, Statement]]:
    """All (policy_idx, statement) pairs that currently permit witness w."""
    res: List[Tuple[int, Statement]] = []
    for i, pol in enumerate(policies):
        for s in pol.statements:
            if s.effect != "Allow":
                continue
            if statement_applies(pol, s, w):
                res.append((i, s))
    return res

def baseline_covered_by(pol: Policy, s: Statement, baseline: List[Request]) -> List[Request]:
    """Baseline requests that this *statement* (under its policy kind) allows."""
    cov: List[Request] = []
    for b in baseline:
        if statement_applies(pol, s, b):
            cov.append(b)
    return cov

def normalize_weights(weights: Optional[Dict[str, int]] = None) -> Dict[str, int]:
    merged = dict(DEFAULT_WEIGHTS)
    if weights:
        merged.update({k: int(v) for k, v in weights.items()})
    if "R5" in merged and "R4" not in merged:
        merged["R4"] = int(merged["R5"])
    merged.pop("R5", None)
    return merged


def gen_R1_action_shrink(pol: Policy, s: Statement, w: Request, base_cov: List[Request],
                         weights: Optional[Dict[str, int]] = None) -> List[Edit]:
    edits: List[Edit] = []
    weights = normalize_weights(weights)
    if w.action not in expand_action_wildcards(s.actions):
        return edits
    edits.append(Edit(kind="R1", target=Target(policy_idx=-1, sid=s.sid),
                      payload=("remove_action", w.action), weight=weights["R1"]))
    # Replace with read-only set if we know the service
    svc = action_service(w.action)
    if svc and any(a in expand_action_wildcards(s.actions) for a in ACTION_CATALOGS.get(svc, set()) - READ_ONLY_SETS.get(svc, set())):
        edits.append(Edit(kind="R1", target=Target(policy_idx=-1, sid=s.sid),
                          payload=("set_actions", sorted(READ_ONLY_SETS[svc])), weight=weights["R1"]))
    return edits

def gen_R2_resource_narrow(pol: Policy, s: Statement, w: Request, base_cov: List[Request],
                           weights: Optional[Dict[str, int]] = None) -> List[Edit]:
    edits: List[Edit] = []
    weights = normalize_weights(weights)
    wres = w.resource
    # Collect baseline "good" resources covered by this statement
    G = [b.resource for b in base_cov]

    # Service-aware narrowing
    if wres.startswith("arn:aws:s3:::"):
        wbucket, wkey = s3_parse_arn(wres)
        good_keys = []
        for r in G:
            b_bucket, b_key = s3_parse_arn(r)
            if b_bucket == wbucket and b_key:
                good_keys.append(b_key)
        if good_keys:
            prefix = key_common_prefix_excluding(good_keys, wkey)
            if prefix:
                new_res = [f"arn:aws:s3:::{wbucket}/{prefix}*"]
                edits.append(Edit(kind="R2", target=Target(policy_idx=-1, sid=s.sid),
                                  payload=("set_resources", tuple(new_res)), weight=weights["R2"],
                                  group=f"R2_{s.sid}"))
    else:
        # Generic: string prefix over full ARN
        prefix = generic_prefix_excluding(G, wres) if G else None
        if prefix:
            # add wildcard to keep it glob-like
            new_res = [prefix + "*"]
            edits.append(Edit(kind="R2", target=Target(policy_idx=-1, sid=s.sid),
                              payload=("set_resources", tuple(new_res)), weight=weights["R2"],
                              group=f"R2_{s.sid}"))
    return edits

def gen_R3_condition_strengthen(pol: Policy, s: Statement, w: Request, base_cov: List[Request],
                                weights: Optional[Dict[str, int]] = None) -> List[Edit]:
    edits: List[Edit] = []
    weights = normalize_weights(weights)
    # Simple key: aws:PrincipalOrgID
    org_values = []
    for b in base_cov:
        if "aws:PrincipalOrgID" in b.gamma:
            org_values.append(str(b.gamma["aws:PrincipalOrgID"]))
    if org_values:
        vstar = max(set(org_values), key=org_values.count)
        if str(w.gamma.get("aws:PrincipalOrgID", "")) != vstar:
            edits.append(Edit(kind="R3", target=Target(policy_idx=-1, sid=s.sid),
                              payload=("add_cond", "aws:PrincipalOrgID", vstar),
                              weight=weights["R3"]))
    # You may add other condition keys like aws:SourceVpce, resource tags, etc.
    return edits

def gen_R4_targeted_deny(pol: Policy, s: Statement, w: Request,
                         weights: Optional[Dict[str, int]] = None) -> Edit:
    weights = normalize_weights(weights)
    deny_stmt = ("deny",
                 [w.principal],
                 [w.action],
                 [w.resource],
                 tuple(sorted((k, str(v)) for k, v in w.gamma.items())))
    return Edit(kind="R4", target=Target(policy_idx=-1, sid=s.sid), payload=deny_stmt, weight=weights["R4"])

def generate_candidates(policies: List[Policy], w: Request, baseline: List[Request],
                        weights: Optional[Dict[str, int]] = None) -> List[Edit]:
    cand: List[Edit] = []
    weights = normalize_weights(weights)
    cov = cov_statements(policies, w)
    if not cov:
        # If for some reason no statement matched (shouldn't happen if witness is permitted), fall back to global deny
        cand.append(Edit(kind="R4", target=Target(policy_idx=0, sid="NEW"),
                         payload=("deny", [w.principal], [w.action], [w.resource], tuple()), weight=weights["R4"]))
        return cand

    for (pi, s) in cov:
        pol = policies[pi]
        base_cov = baseline_covered_by(pol, s, baseline)
        e1 = gen_R2_resource_narrow(pol, s, w, base_cov, weights)
        e2 = gen_R3_condition_strengthen(pol, s, w, base_cov, weights)
        e3 = gen_R1_action_shrink(pol, s, w, base_cov, weights)
        # Bind target policy index for each edit
        for e in e1 + e2 + e3:
            object.__setattr__(e, "target", Target(policy_idx=pi, sid=s.sid))
            cand.append(e)
        if not (e1 or e2 or e3):
            # As last resort per covering statement
            cand.append(gen_R4_targeted_deny(pol, s, w, weights))
            object.__setattr__(cand[-1], "target", Target(policy_idx=pi, sid=s.sid))
    return cand


# -------------------------------
# Apply & Simulate Edits
# -------------------------------

def find_statement_index(pol: Policy, sid: str) -> int:
    for i, st in enumerate(pol.statements):
        if st.sid == sid:
            return i
    return -1

def apply_edit(policies: List[Policy], e: Edit) -> List[Policy]:
    """Apply one edit to a deep copy of policies."""
    P = copy.deepcopy(policies)
    pi = e.target.policy_idx
    if pi < 0 or pi >= len(P):
        return P
    pol = P[pi]

    if e.kind in ("R1", "R2", "R3"):
        idx = find_statement_index(pol, e.target.sid)
        if idx < 0:
            return P
        s = pol.statements[idx]
        op = e.payload[0]
        if e.kind == "R1":
            if op == "remove_action":
                act = e.payload[1]
                expanded = expand_action_wildcards(s.actions)
                if act in expanded:
                    new_actions = sorted(expanded - {act})
                    s.actions = new_actions
            elif op == "set_actions":
                new_list = list(e.payload[1])
                s.actions = new_list
        elif e.kind == "R2" and op == "set_resources":
            s.resources = list(e.payload[1])
        elif e.kind == "R3" and op == "add_cond":
            k, v = e.payload[1], e.payload[2]
            s.conditions[k] = v
    elif e.kind == "R4":
        # add a Deny in the same policy, new sid
        _kind, principals, actions, resources, cond_tuples = e.payload
        conds = {k: v for (k, v) in cond_tuples}
        new_sid = f"Deny_{len(pol.statements)+1}"
        pol.statements.append(Statement(
            sid=new_sid, effect="Deny",
            principals=list(principals),
            actions=list(actions),
            resources=list(resources),
            conditions=conds
        ))
    return P

def apply_edits(policies: List[Policy], selected: List[Edit]) -> List[Policy]:
    P = copy.deepcopy(policies)
    for e in selected:
        P = apply_edit(P, e)
    return P

def kills_witness(policies: List[Policy], e: Edit, w: Request, baseline: List[Request]) -> bool:
    P2 = apply_edit(policies, e)
    if permit(P2, w):
        return False
    for b in baseline:
        if not permit(P2, b):
            return False
    return True

def kills_baseline(policies: List[Policy], e: Edit, b: Request) -> bool:
    P2 = apply_edit(policies, e)
    return not permit(P2, b)


# -------------------------------
# MaxSMT-style Selection (z3 Optimize)
# -------------------------------

def pick_min_cost_edits(policies: List[Policy],
                        witnesses: List[Request],
                        baseline: List[Request],
                        candidates: List[Edit]) -> List[Edit]:
    """Weighted hitting-set with hard baseline constraints and optional mutex groups."""
    if not candidates:
        return []
    K_w = {i: [] for i in range(len(witnesses))}
    K_b = {j: [] for j in range(len(baseline))}
    for idx, e in enumerate(candidates):
        for i, w in enumerate(witnesses):
            if kills_witness(policies, e, w, baseline):
                K_w[i].append(idx)
        for j, b in enumerate(baseline):
            if kills_baseline(policies, e, b):
                K_b[j].append(idx)

    opt = Optimize()
    X = [Bool(f"x_{k}") for k in range(len(candidates))]

    # Cover witnesses
    for i, idxs in K_w.items():
        if idxs:
            opt.add(Or(*[X[k] for k in idxs]))

    # Keep baseline: do not choose any edit that breaks baseline
    for j, idxs in K_b.items():
        for k in idxs:
            opt.add(X[k] == False)

    # Mutex per R2 group
    groups: Dict[str, List[int]] = {}
    for k, e in enumerate(candidates):
        if e.group:
            groups.setdefault(e.group, []).append(k)
    for g, idxs in groups.items():
        for a in range(len(idxs)):
            for b in range(a+1, len(idxs)):
                opt.add(Or(Not(X[idxs[a]]), Not(X[idxs[b]])))

    objective = Sum([IntVal(candidates[k].weight) * If(X[k], IntVal(1), IntVal(0)) for k in range(len(candidates))])
    opt.minimize(objective)

    if opt.check() != sat:
        return []
    m = opt.model()
    return [candidates[k] for k in range(len(candidates)) if bool(m.eval(X[k], model_completion=True))]


# -------------------------------
# CEGIS Loop
# -------------------------------

def cegis_repair(policies: List[Policy],
                 p1: AllowEnvelope,
                 p2: ForbidSlice,
                 baseline: List[Request],
                 weights: Dict[str, int],
                 max_iters: int = 10,
                 verbose: bool = True) -> List[Policy]:
    W: List[Request] = []
    # Optional pre-processing: try to merge statements per policy.
    try:
        P = merge_policies_for_repair(policies)
    except ValueError as e:
        if verbose:
            print(f"[Merge] Conflict detected: {e}")
            print("[Merge] Refusing to repair this input policy set.")
        # Return original policies unchanged when merge-based repair is not applicable.
        return copy.deepcopy(policies)

    for it in range(1, max_iters+1):
        res = verify(P, p1, p2, baseline)
        if res.sat:
            if verbose:
                print(f"[Iter {it}] SAT: all properties satisfied.")
            return P
        w = res.witness
        assert w is not None
        W.append(w)
        if verbose:
            print(f"[Iter {it}] Witness({res.kind}): principal={w.principal}, action={w.action}, resource={w.resource}")

        # Rebuild candidates from all witnesses on current P
        E: List[Edit] = []
        for u in W:
            E.extend(generate_candidates(P, u, baseline, weights))

        if verbose:
            print(f"[Iter {it}] Candidates: {len(E)}  " +
                  ", ".join(f"{e.kind}:{e.weight}@pol{e.target.policy_idx}:{e.target.sid}" for e in E))

        chosen = pick_min_cost_edits(P, W, baseline, E)
        if not chosen:
            if verbose:
                print(f"[Iter {it}] No feasible edit set found. Stop.")
            return P

        if verbose:
            for e in chosen:
                print(f"  -> Apply {e.kind} on policy[{e.target.policy_idx}] sid={e.target.sid}: {e.payload}  (w={e.weight})")
        P = apply_edits(P, chosen)

    if verbose:
        print("[Warn] Reached max iters without SAT.")
    return P


# -------------------------------
# IO Layer
# -------------------------------

@dataclass
class Experiment:
    """All experiment inputs: policies, properties, baseline, weights/config."""
    policies: List[Policy]
    p1: AllowEnvelope
    p2: ForbidSlice
    baseline: List[Request]
    weights: Dict[str, int]
    max_iters: int
    verbose: bool

class PolicyLoader:
    """Load JSON: supports new 'policies' array or legacy single 'policy' dict."""
    @staticmethod
    def load_json(path: str) -> Experiment:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)

        policies: List[Policy] = []
        if "policies" in d:
            for pol in d["policies"]:
                stmts = []
                for s in pol["statements"]:
                    stmts.append(Statement(
                        sid=s.get("sid","S"),
                        effect=s["effect"],
                        principals=list(s.get("principals", [])),
                        actions=list(s.get("actions", [])),
                        resources=list(s.get("resources", [])),
                        conditions=dict(s.get("conditions", {})),
                    ))
                policies.append(Policy(
                    kind=pol.get("kind","identity"),
                    statements=stmts,
                    attached_principals=list(pol.get("attached_principals", [])),
                ))
        elif "policy" in d:
            # Legacy: single resource-based policy
            sdefs = []
            for s in d["policy"]["statements"]:
                sdefs.append(Statement(
                    sid=s.get("sid","S"),
                    effect=s["effect"],
                    principals=list(s.get("principals", [])),
                    actions=list(s.get("actions", [])),
                    resources=list(s.get("resources", [])),
                    conditions=dict(s.get("conditions", {})),
                ))
            # assume resource-based legacy
            policies.append(Policy(kind="resource", statements=sdefs))
        else:
            raise ValueError("JSON must contain 'policies' or legacy 'policy'.")

        # properties
        p1d = d["properties"]["p1"]
        p2d = d["properties"]["p2"]
        p1 = AllowEnvelope(actions=set(p1d.get("actions", [])),
                           resource_prefixes=list(p1d.get("resource_prefixes", [])))
        p2 = ForbidSlice(actions=set(p2d.get("actions", [])),
                         resource_prefixes=list(p2d.get("resource_prefixes", [])))

        # baseline
        baseline = [Request(principal=b["principal"], action=b["action"], resource=b["resource"], gamma=dict(b.get("gamma", {})))
                    for b in d.get("baseline", [])]

        # weights and config
        weights = normalize_weights(d.get("weights", {}))
        max_iters = int(d.get("max_iters", 8))
        verbose = bool(d.get("verbose", True))

        return Experiment(policies=policies, p1=p1, p2=p2, baseline=baseline,
                          weights=weights, max_iters=max_iters, verbose=verbose)

def policies_to_dict(policies: List[Policy]) -> Dict[str, Any]:
    """Serialize policies to JSON-friendly dict."""
    out = []
    for pol in policies:
        out.append({
            "kind": pol.kind,
            "attached_principals": pol.attached_principals,
            "statements": [{
                "sid": s.sid,
                "effect": s.effect,
                "principals": s.principals,
                "actions": s.actions,
                "resources": s.resources,
                "conditions": s.conditions,
            } for s in pol.statements]
        })
    return {"policies": out}


# -------------------------------
# CLI
# -------------------------------

# -------------------------------
# Evaluation Helpers
# -------------------------------

def evaluate_policy(policies: List[Policy],
                    p1: AllowEnvelope,
                    p2: ForbidSlice,
                    baseline: List[Request]) -> Dict[str, Any]:
    """
    Compute evaluation metrics for a given policy set:
      - sat_all: whether Baseline, P2, and P1 are all satisfied (as in SatAll).
      - out_of_env_rate: fraction of permitted queries that fall outside the P1 envelope
                         (analogous to OutOfEnvRate(U) in the paper).
      - counts of forbidden violations, out-of-envelope permits, and broken baseline queries.
    The universe U is built using the same enumeration as verify().
    """
    principals, actions, resources = build_universe(policies, p1, p2, baseline)

    total_permitted = 0
    out_of_env_count = 0
    forb_viol_count = 0

    # Enumerate U and accumulate statistics
    for pr in principals:
        for a in actions:
            for r in resources:
                q = Request(principal=pr, action=a, resource=r, gamma={})
                if not permit(policies, q):
                    continue
                total_permitted += 1
                if not p1.in_envelope(q):
                    out_of_env_count += 1
                if p2.is_forbidden(q):
                    forb_viol_count += 1

    # Baseline violations
    baseline_viol_count = sum(1 for b in baseline if not permit(policies, b))

    # OutOfEnvRate(U) = (# permitted outside envelope) / max(1, # permitted)
    denom = max(1, total_permitted)
    out_of_env_rate = out_of_env_count / denom

    # SatAll: Baseline OK, no P2-violating permits, no out-of-envelope permits
    sat_all = (baseline_viol_count == 0 and
               forb_viol_count == 0 and
               out_of_env_count == 0)

    return {
        "sat_all": sat_all,
        "total_permitted": total_permitted,
        "out_of_env_count": out_of_env_count,
        "out_of_env_rate": out_of_env_rate,
        "forbid_violations": forb_viol_count,
        "baseline_violations": baseline_viol_count,
    }

def main():
    ap = argparse.ArgumentParser(description="PolicyRepair (CEGIS-Repair) Multi-Service prototype")
    ap.add_argument("--input", "-i", required=True, help="Experiment JSON (supports 'policies' or legacy 'policy')")
    ap.add_argument("--out", "-o", default="repaired_policies.json", help="Output repaired policies JSON")
    ap.add_argument("--iters", type=int, default=None, help="Override max iters")
    ap.add_argument("--quiet", action="store_true", help="Suppress verbose logs")
    args = ap.parse_args()

    exp = PolicyLoader.load_json(args.input)
    if args.iters is not None:
        exp.max_iters = args.iters
    verbose = False if args.quiet else exp.verbose

    # --- Evaluation of original policies ---
    orig_metrics = evaluate_policy(exp.policies, exp.p1, exp.p2, exp.baseline)
    if verbose:
        print("[Eval] Original policy metrics:")
        for k, v in orig_metrics.items():
            print(f"  {k}: {v}")

    # --- Run CEGIS repair ---
    repaired = cegis_repair(exp.policies, exp.p1, exp.p2, exp.baseline,
                            weights=exp.weights,
                            max_iters=exp.max_iters,
                            verbose=verbose)

    # --- Evaluation of repaired policies ---
    repaired_metrics = evaluate_policy(repaired, exp.p1, exp.p2, exp.baseline)
    if verbose:
        print("\n[Eval] Repaired policy metrics:")
        for k, v in repaired_metrics.items():
            print(f"  {k}: {v}")

    # --- Output JSON: include both policies and metrics ---
    out_obj = {
        "policy_original": policies_to_dict(exp.policies),
        "policy_repaired": policies_to_dict(repaired),
        "metrics": {
            "original": orig_metrics,
            "repaired": repaired_metrics,
        },
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, ensure_ascii=False, indent=2)
    if verbose:
        print(f"\nSaved repaired policies to: {args.out}")

if __name__ == "__main__":
    main()
