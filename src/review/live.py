"""Checks a live AWS account through read-only API calls.

Every call here is a Describe, Get or List call covered by the AWS managed SecurityAudit policy, which is what the
review role in terraform/ grants (sts:GetCallerIdentity needs no permission). Nothing is changed in the account.
"""
import json
from datetime import UTC, datetime, timedelta

import boto3
from botocore.exceptions import ClientError

from .findings import Finding

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = (22, 3389)
KEY_AGE = timedelta(days=90)


def _code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "")


def _pages(client, op: str, key: str, **kw):
    for page in client.get_paginator(op).paginate(**kw):
        yield from page.get(key, [])


def _iam(session: boto3.Session) -> list[Finding]:
    """The root user, IAM keys and customer managed policies. IAM is global."""
    out = []
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountAccessKeysPresent"):
        out.append(Finding("ROOT_KEYS", "root", "global"))
    if not summary.get("AccountMFAEnabled"):
        out.append(Finding("ROOT_NO_MFA", "root", "global"))

    now = datetime.now(UTC)
    for user in _pages(iam, "list_users", "Users"):
        for key in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
            if key["Status"] == "Active" and now - key["CreateDate"] > KEY_AGE:
                age = (now - key["CreateDate"]).days
                out.append(Finding("OLD_ACCESS_KEY", user["Arn"], "global", f"{age} days old"))

    for pol in _pages(iam, "list_policies", "Policies", Scope="Local", OnlyAttached=True):
        doc = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])["PolicyVersion"]["Document"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        if _allows_everything(doc):
            out.append(Finding("IAM_WILDCARD", pol["Arn"], "global"))
    return out


def _allows_everything(doc: dict) -> bool:
    stmts = doc.get("Statement", [])
    for s in stmts if isinstance(stmts, list) else [stmts]:
        actions = s.get("Action", [])
        resources = s.get("Resource", [])
        actions = actions if isinstance(actions, list) else [actions]
        resources = resources if isinstance(resources, list) else [resources]
        if s.get("Effect") == "Allow" and "*" in actions and "*" in resources and "Condition" not in s:
            return True
    return False


def _s3(session: boto3.Session) -> list[Finding]:
    out = []
    s3 = session.client("s3")
    account = session.client("sts").get_caller_identity()["Account"]
    try:
        cfg = session.client("s3control").get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"]
        account_blocked = all(cfg.values())
    except ClientError as e:
        if _code(e) != "NoSuchPublicAccessBlockConfiguration":
            raise
        account_blocked = False

    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        region = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        arn = f"arn:aws:s3:::{name}"
        if not account_blocked:
            try:
                cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                blocked = all(cfg.values())
            except ClientError as e:
                if _code(e) != "NoSuchPublicAccessBlockConfiguration":
                    raise
                blocked = False
            if not blocked:
                out.append(Finding("S3_PUBLIC_ACCESS", arn, region))
        try:
            policy = s3.get_bucket_policy(Bucket=name)["Policy"]
        except ClientError as e:
            if _code(e) != "NoSuchBucketPolicy":
                raise
            policy = ""
        if "aws:SecureTransport" not in policy:
            out.append(Finding("S3_TLS_ONLY", arn, region))
        try:
            s3.get_bucket_lifecycle_configuration(Bucket=name)
        except ClientError as e:
            if _code(e) != "NoSuchLifecycleConfiguration":
                raise
            out.append(Finding("S3_NO_LIFECYCLE", arn, region))
        if s3.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
            out.append(Finding("S3_NO_VERSIONING", arn, region))
    return out


DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthFailure", "UnrecognizedClientException"}


def _ec2(session: boto3.Session, region: str) -> list[Finding]:
    out = []
    ec2 = session.client("ec2", region_name=region)

    if not ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
        out.append(Finding("EBS_DEFAULT_ENCRYPTION_OFF", region, region))

    for sg in _pages(ec2, "describe_security_groups", "SecurityGroups"):
        for perm in sg.get("IpPermissions", []):
            cidrs = {r["CidrIp"] for r in perm.get("IpRanges", [])} | {r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])}
            if not cidrs & OPEN_CIDRS:
                continue
            if perm["IpProtocol"] == "-1":
                out.append(Finding("SG_ADMIN_OPEN", sg["GroupId"], region, "all ports"))
                continue
            lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 0)
            hits = [str(p) for p in ADMIN_PORTS if lo <= p <= hi]
            if hits:
                out.append(Finding("SG_ADMIN_OPEN", sg["GroupId"], region, "port " + ", ".join(hits)))

    for res in _pages(ec2, "describe_instances", "Reservations"):
        for i in res["Instances"]:
            if i["State"]["Name"] == "terminated":
                continue
            if i.get("MetadataOptions", {}).get("HttpTokens") != "required":
                out.append(Finding("IMDS_V1", i["InstanceId"], region))

    for v in _pages(ec2, "describe_volumes", "Volumes"):
        if not v.get("Encrypted"):
            out.append(Finding("EBS_UNENCRYPTED", v["VolumeId"], region))
        if v.get("VolumeType") == "gp2":
            out.append(Finding("EBS_GP2", v["VolumeId"], region, f"{v['Size']} GiB"))
        if v.get("State") == "available":
            out.append(Finding("EBS_UNATTACHED", v["VolumeId"], region, f"{v['Size']} GiB"))

    for a in ec2.describe_addresses().get("Addresses", []):
        if "AssociationId" not in a:
            out.append(Finding("EIP_UNUSED", a.get("AllocationId", a.get("PublicIp", "")), region))
    return out


def _rds(session: boto3.Session, region: str) -> list[Finding]:
    out = []
    rds = session.client("rds", region_name=region)
    for db in _pages(rds, "describe_db_instances", "DBInstances"):
        arn = db["DBInstanceArn"]
        if not db.get("StorageEncrypted"):
            out.append(Finding("RDS_UNENCRYPTED", arn, region))
        if db.get("PubliclyAccessible"):
            out.append(Finding("RDS_PUBLIC", arn, region))
        if db.get("BackupRetentionPeriod", 0) == 0:
            out.append(Finding("RDS_NO_BACKUP", arn, region))
        if not db.get("MultiAZ"):
            out.append(Finding("RDS_SINGLE_AZ", arn, region))
    return out


def _cloudtrail(session: boto3.Session, region: str) -> list[Finding]:
    ct = session.client("cloudtrail", region_name=region)
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    logging = [t for t in trails if t.get("IsMultiRegionTrail")
               and ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging")]
    return [] if logging else [Finding("NO_CLOUDTRAIL", "cloudtrail", region)]


def _logs(session: boto3.Session, region: str) -> list[Finding]:
    out = []
    logs = session.client("logs", region_name=region)
    for g in _pages(logs, "describe_log_groups", "logGroups"):
        if not g.get("retentionInDays"):
            out.append(Finding("LOG_NO_RETENTION", g["logGroupName"], region))
    return out


def _dynamodb(session: boto3.Session, region: str) -> list[Finding]:
    out = []
    ddb = session.client("dynamodb", region_name=region)
    for name in _pages(ddb, "list_tables", "TableNames"):
        pitr = ddb.describe_continuous_backups(TableName=name)["ContinuousBackupsDescription"]
        if pitr.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus") != "ENABLED":
            out.append(Finding("DDB_NO_PITR", name, region))
    return out


def _lambda(session: boto3.Session, region: str) -> list[Finding]:
    out = []
    lam = session.client("lambda", region_name=region)
    for fn in _pages(lam, "list_functions", "Functions"):
        for url in lam.list_function_url_configs(FunctionName=fn["FunctionName"]).get("FunctionUrlConfigs", []):
            if url.get("AuthType") == "NONE":
                out.append(Finding("LAMBDA_URL_OPEN", fn["FunctionArn"], region))
    return out


def session_for(role_arn: str | None, external_id: str | None, profile: str | None = None) -> boto3.Session:
    """The caller's own credentials, or the client's review role assumed with its external id."""
    base = boto3.Session(profile_name=profile)
    if not role_arn:
        return base
    kw = {"RoleArn": role_arn, "RoleSessionName": "security-cost-review", "DurationSeconds": 3600}
    if external_id:
        kw["ExternalId"] = external_id
    c = base.client("sts").assume_role(**kw)["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                         aws_session_token=c["SessionToken"])


REGIONAL = {"EC2": _ec2, "RDS": _rds, "CloudTrail": _cloudtrail, "CloudWatch Logs": _logs, "DynamoDB": _dynamodb,
            "Lambda": _lambda}


def check(session: boto3.Session, regions: list[str]) -> tuple[list[Finding], list[str]]:
    """The findings, and what couldn't be checked because the call was refused (a policy or SCP denies it)."""
    out, skipped = [], []

    def run(label: str, fn, *args):
        try:
            out.extend(fn(session, *args))
        except ClientError as e:
            if _code(e) not in DENIED:
                raise
            skipped.append(f"{label}: {_code(e)}")

    run("IAM", _iam)
    run("S3", _s3)
    for r in regions:
        for name, fn in REGIONAL.items():
            run(f"{name} in {r}", fn, r)
    return out, skipped
