"""Checks Terraform files without running Terraform or touching AWS.

Values that come from variables or other resources can't be known without a plan, so a rule only fires on what the
file states, or on a setting that is missing altogether. The report says so.
"""
import re
from dataclasses import dataclass
from pathlib import Path

import hcl2

from .findings import Finding

SKIP_DIRS = {".terraform", ".git", "node_modules", ".venv"}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = (22, 3389)


@dataclass
class Resource:
    type: str
    name: str
    body: dict
    file: Path
    line: int
    text: str       # the block's source, for references and policies written inline

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"

    def where(self, root: Path) -> str:
        return f"{self.file.relative_to(root)}:{self.line}"


def unquote(v):
    """hcl2 keeps string quotes; references and expressions come back as ${...}."""
    if isinstance(v, str) and len(v) >= 2 and v[0] == v[-1] == '"':
        return v[1:-1]
    return v


def literal(v) -> bool:
    v = unquote(v)
    return not (isinstance(v, str) and ("${" in v or v.startswith(("var.", "local.", "data.", "module."))))


def blocks(body: dict, key: str) -> list[dict]:
    v = body.get(key, [])
    return [b for b in (v if isinstance(v, list) else [v]) if isinstance(b, dict)]


def _block_text(src: str, start: int) -> str:
    """The text of a block from its opening line to the matching closing brace."""
    depth, i = 0, src.index("{", start)
    for j in range(i, len(src)):
        depth += {"{": 1, "}": -1}.get(src[j], 0)
        if depth == 0:
            return src[start:j + 1]
    return src[start:]


ACCEPT = re.compile(r"#\s*review:\s*accept\s+([A-Z0-9_]+)\s*(.*)")


def load(root: Path) -> tuple[list[Resource], list[Resource], dict]:
    """Every resource and data block under root, with its file and line, and every local value's source."""
    resources, data, locals_ = [], [], {}
    for f in sorted(root.rglob("*.tf")):
        if SKIP_DIRS & set(f.relative_to(root).parts):
            continue
        src = f.read_text()
        parsed = hcl2.loads(src)
        for block in parsed.get("locals", []):
            for k, v in block.items():
                locals_[k] = str(v)
        for kind, out in (("resource", resources), ("data", data)):
            for item in parsed.get(kind, []):
                for rtype, named in item.items():
                    for name, body in named.items():
                        t, n = unquote(rtype), unquote(name)
                        m = re.search(rf'^[ \t]*{kind}\s+"{re.escape(t)}"\s+"{re.escape(n)}"', src, re.MULTILINE)
                        line = src[:m.start()].count("\n") + 1 if m else 0
                        text = _block_text(src, m.start()) if m else ""
                        out.append(Resource(t, n, body, f, line, text))
    return resources, data, locals_


def _refers_to(r: Resource, target: Resource) -> bool:
    return re.search(rf"\b{re.escape(target.address)}\b", r.text) is not None


def _all_true(r: Resource, keys: list[str]) -> bool:
    return all(unquote(r.body.get(k)) is True for k in keys)


PAB_KEYS = ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]


def accepted(r: Resource) -> dict[str, str]:
    """Rules accepted on purpose, from a comment inside the block: # review: accept RULE_ID the reason."""
    return {m.group(1): m.group(2).strip() for m in ACCEPT.finditer(r.text)}


def check(root: Path) -> list[Finding]:
    root = root.resolve()
    res, data, locals_ = load(root)
    by_type: dict[str, list[Resource]] = {}
    for r in res:
        by_type.setdefault(r.type, []).append(r)
    def of(t: str) -> list[Resource]:
        return by_type.get(t, [])

    out: list[Finding] = []

    def add(rule, r: Resource, detail=""):
        reason = accepted(r).get(rule)
        out.append(Finding(rule, r.address, r.where(root), detail, accepted=reason))

    # S3
    account_pab = any(_all_true(r, PAB_KEYS) for r in of("aws_s3_account_public_access_block"))
    for b in of("aws_s3_bucket"):
        def related(t: str, b: Resource = b) -> list[Resource]:
            return [r for r in of(t) if _refers_to(r, b)]

        if not account_pab and not any(_all_true(p, PAB_KEYS) for p in related("aws_s3_bucket_public_access_block")):
            add("S3_PUBLIC_ACCESS", b)
        policies = related("aws_s3_bucket_policy")
        policy_text = " ".join(p.text for p in policies)
        policy_text += " ".join(v for k, v in locals_.items() if re.search(rf"\blocal\.{re.escape(k)}\b", policy_text))
        policy_text += " ".join(d.text for d in data if d.type == "aws_iam_policy_document"
                                and re.search(rf"\bdata\.{d.type}\.{d.name}\b", policy_text))
        if "aws:SecureTransport" not in policy_text:
            add("S3_TLS_ONLY", b)
        if not related("aws_s3_bucket_lifecycle_configuration"):
            add("S3_NO_LIFECYCLE", b)
        if not any(re.search(r'status\s*=\s*"Enabled"', v.text) for v in related("aws_s3_bucket_versioning")):
            add("S3_NO_VERSIONING", b)

    # Databases
    for db in of("aws_db_instance") + of("aws_rds_cluster"):
        b = db.body
        enc = unquote(b.get("storage_encrypted"))
        if enc is not True and literal(b.get("storage_encrypted", False)):
            # aws_rds_cluster for Aurora Serverless v1 is encrypted regardless; that engine mode is retired
            add("RDS_UNENCRYPTED", db)
        if unquote(b.get("publicly_accessible")) is True:
            add("RDS_PUBLIC", db)
        if str(unquote(b.get("backup_retention_period", ""))) == "0":
            add("RDS_NO_BACKUP", db)
        if db.type == "aws_db_instance" and unquote(b.get("multi_az")) is not True and literal(b.get("multi_az", False)):
            add("RDS_SINGLE_AZ", db)
        for key in ("password", "master_password"):
            if key in b and literal(b[key]) and unquote(b[key]):
                add("PLAINTEXT_SECRET", db, key)

    # Security groups
    def open_admin(rule: dict) -> str | None:
        cidrs = set()
        for k in ("cidr_blocks", "ipv6_cidr_blocks"):
            v = rule.get(k) or []
            cidrs |= {unquote(c) for c in (v if isinstance(v, list) else [v])}
        for k in ("cidr_ipv4", "cidr_ipv6"):
            if k in rule:
                cidrs.add(unquote(rule[k]))
        if not cidrs & OPEN_CIDRS:
            return None
        proto = str(unquote(rule.get("protocol", rule.get("ip_protocol", ""))))
        if proto in ("-1", "all"):
            return "all ports"
        try:
            lo, hi = int(unquote(rule.get("from_port"))), int(unquote(rule.get("to_port")))
        except (TypeError, ValueError):
            return None
        hits = [str(p) for p in ADMIN_PORTS if lo <= p <= hi]
        return "port " + ", ".join(hits) if hits else None

    for sg in of("aws_security_group"):
        for ing in blocks(sg.body, "ingress"):
            if d := open_admin(ing):
                add("SG_ADMIN_OPEN", sg, d)
    for r in of("aws_security_group_rule"):
        if unquote(r.body.get("type")) == "ingress" and (d := open_admin(r.body)):
            add("SG_ADMIN_OPEN", r, d)
    for r in of("aws_vpc_security_group_ingress_rule"):
        if d := open_admin(r.body):
            add("SG_ADMIN_OPEN", r, d)

    # IAM: a statement allowing every action on every resource, in jsonencode or a policy document
    wildcard = re.compile(
        r'(?is)(effect\s*=\s*"Allow"[^}]*?(actions?\s*=\s*\[?\s*"\*"\s*\]?)[^}]*?(resources?\s*=\s*\[?\s*"\*"\s*\]?))'
        r'|((actions?\s*=\s*\[?\s*"\*"\s*\]?)[^}]*?(resources?\s*=\s*\[?\s*"\*"\s*\]?)[^}]*?effect\s*=\s*"Allow")')
    for r in res + data:
        if r.type in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy",
                      "aws_iam_policy_document") and wildcard.search(r.text):
            out.append(Finding("IAM_WILDCARD", ("data." if r in data else "") + r.address, r.where(root)))

    # Compute
    default_ebs = any(unquote(r.body.get("enabled")) is True for r in of("aws_ebs_encryption_by_default"))
    for v in of("aws_ebs_volume"):
        if not default_ebs and unquote(v.body.get("encrypted")) is not True:
            add("EBS_UNENCRYPTED", v)
        if unquote(v.body.get("type")) == "gp2":
            add("EBS_GP2", v)
    for i in of("aws_instance") + of("aws_launch_template"):
        meta = blocks(i.body, "metadata_options")
        if not meta or unquote(meta[0].get("http_tokens")) != "required":
            add("IMDS_V1", i)
        for disk in blocks(i.body, "root_block_device") + blocks(i.body, "ebs_block_device"):
            if not default_ebs and unquote(disk.get("encrypted")) is not True:
                add("EBS_UNENCRYPTED", i, "root or attached volume")
            if unquote(disk.get("volume_type")) == "gp2":
                add("EBS_GP2", i)
        for bdm in blocks(i.body, "block_device_mappings"):
            for e in blocks(bdm, "ebs"):
                if not default_ebs and unquote(e.get("encrypted")) not in (True, "true"):
                    add("EBS_UNENCRYPTED", i, "launch template volume")
                if unquote(e.get("volume_type")) == "gp2":
                    add("EBS_GP2", i)

    for u in of("aws_lambda_function_url"):
        if unquote(u.body.get("authorization_type")) == "NONE":
            add("LAMBDA_URL_OPEN", u)

    for t in of("aws_dynamodb_table"):
        pitr = blocks(t.body, "point_in_time_recovery")
        if not pitr or unquote(pitr[0].get("enabled")) is not True:
            add("DDB_NO_PITR", t)

    for g in of("aws_cloudwatch_log_group"):
        if "retention_in_days" not in g.body or str(unquote(g.body["retention_in_days"])) == "0":
            add("LOG_NO_RETENTION", g)

    return out
