import json

import boto3
import pytest
from moto import mock_aws

from review import live

REGION = "eu-west-2"


@pytest.fixture
def session(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        yield boto3.Session(region_name=REGION)


def rules(findings):
    return {f.rule for f in findings}


def test_flawed_resources_are_found(session):
    ec2 = session.client("ec2")
    sg = ec2.create_security_group(GroupName="web", Description="web")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=50, VolumeType="gp2")
    ec2.allocate_address(Domain="vpc")
    session.client("logs").create_log_group(logGroupName="/app")
    session.client("s3").create_bucket(Bucket="uploads", CreateBucketConfiguration={"LocationConstraint": REGION})
    session.client("rds").create_db_instance(DBInstanceIdentifier="orders", DBInstanceClass="db.t4g.micro",
                                             Engine="postgres", MasterUsername="app", MasterUserPassword="x" * 16,
                                             AllocatedStorage=20, PubliclyAccessible=True, BackupRetentionPeriod=0)
    found, skipped = live.check(session, [REGION])
    assert skipped == []
    assert {"SG_ADMIN_OPEN", "EBS_GP2", "EBS_UNATTACHED", "EBS_UNENCRYPTED", "EIP_UNUSED", "LOG_NO_RETENTION",
            "S3_PUBLIC_ACCESS", "S3_TLS_ONLY", "S3_NO_LIFECYCLE", "S3_NO_VERSIONING", "RDS_UNENCRYPTED",
            "RDS_PUBLIC", "RDS_NO_BACKUP", "RDS_SINGLE_AZ", "NO_CLOUDTRAIL", "EBS_DEFAULT_ENCRYPTION_OFF",
            "ROOT_NO_MFA"} <= rules(found)
    assert [f.detail for f in found if f.rule == "SG_ADMIN_OPEN"] == ["port 3389"]


def test_a_well_set_up_bucket_passes(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="uploads", CreateBucketConfiguration={"LocationConstraint": REGION})
    s3.put_public_access_block(Bucket="uploads", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_policy(Bucket="uploads", Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::uploads/*",
        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))
    s3.put_bucket_versioning(Bucket="uploads", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_lifecycle_configuration(Bucket="uploads", LifecycleConfiguration={"Rules": [
        {"ID": "expire", "Status": "Enabled", "Filter": {}, "Expiration": {"Days": 365}}]})
    assert not {f for f in live.check(session, [REGION])[0] if f.resource == "arn:aws:s3:::uploads"}


def test_an_admin_policy_is_found_but_a_scoped_one_isnt(session):
    iam = session.client("iam")
    iam.create_role(RoleName="app", AssumeRolePolicyDocument="{}")
    for name, action in (("admin", "*"), ("reader", "s3:GetObject")):
        arn = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": action, "Resource": "*"}]}))["Policy"]["Arn"]
        iam.attach_role_policy(RoleName="app", PolicyArn=arn)
    wild = [f.resource for f in live.check(session, [REGION])[0] if f.rule == "IAM_WILDCARD"]
    assert len(wild) == 1 and wild[0].endswith(":policy/admin")


def test_a_refused_service_is_listed_and_the_rest_still_runs(session, monkeypatch):
    from botocore.exceptions import ClientError

    def refused(*_):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": ""}}, "ListFunctions")

    monkeypatch.setitem(live.REGIONAL, "Lambda", refused)
    session.client("logs").create_log_group(logGroupName="/app")
    found, skipped = live.check(session, [REGION])
    assert skipped == [f"Lambda in {REGION}: AccessDeniedException"]
    assert "LOG_NO_RETENTION" in rules(found)
