from botocore.exceptions import ClientError

from review.explain import check_summary, plain, summarise
from review.findings import Finding

FINDINGS = [Finding("RDS_PUBLIC", "aws_db_instance.orders", "main.tf:6"),
            Finding("EBS_GP2", "vol-1", "eu-west-2", "100 GiB"),
            Finding("S3_NO_VERSIONING", "aws_s3_bucket.cache", "main.tf:3", accepted="rebuilt nightly")]


class Bedrock:
    def __init__(self, text=None, error=None):
        self.text, self.error = text, error

    def converse(self, **kw):
        if self.error:
            raise self.error
        return {"output": {"message": {"content": [{"text": self.text}]}}}


def test_a_summary_that_cites_real_findings_is_used():
    text = "The database is open to the internet [1]. The 100 GiB volume could move to gp3 [2]."
    assert summarise(FINDINGS, Bedrock(text)) == (text, "model")


def test_invented_numbers_are_rejected():
    assert check_summary("Fixing [1] saves 40% of the bill.", FINDINGS) == ["uses numbers not in the findings: ['40']"]


def test_citing_a_finding_that_doesnt_exist_is_rejected():
    assert "cites findings that don't exist: [7]" in check_summary("See [7].", FINDINGS)


def test_a_refused_call_falls_back_to_the_plain_summary():
    err = ClientError({"Error": {"Code": "ValidationException", "Message": "Operation not allowed"}}, "Converse")
    text, source = summarise(FINDINGS, Bedrock(error=err))
    assert text == plain(FINDINGS) and source.startswith("plain: the model couldn't be called")


def test_plain_summary_counts_only_open_findings():
    assert plain(FINDINGS) == "2 open findings: 1 high, 1 low. Start with: Database reachable from the internet [1]."


def test_repeated_rules_are_named_once_with_every_instance():
    trails = [Finding("NO_CLOUDTRAIL", "cloudtrail", r) for r in ("eu-west-1", "eu-west-2")]
    assert plain(trails) == "2 open findings: 2 high. Start with: No multi-region CloudTrail trail logging [1, 2]."
    assert check_summary(plain(trails), trails) == []
