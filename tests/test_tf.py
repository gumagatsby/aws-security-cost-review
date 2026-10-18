from collections import Counter
from pathlib import Path

from review.rules import RULES
from review.tf import check

FIX = Path(__file__).parent / "fixtures"
LIVE_ONLY = {"NO_CLOUDTRAIL", "ROOT_KEYS", "ROOT_NO_MFA", "OLD_ACCESS_KEY", "EBS_DEFAULT_ENCRYPTION_OFF",
             "EBS_UNATTACHED", "EIP_UNUSED"}


def test_every_terraform_rule_fires_once_on_the_flawed_file():
    fired = Counter(f.rule for f in check(FIX / "flawed"))
    assert set(fired) == set(RULES) - LIVE_ONLY
    assert all(n == 1 for n in fired.values()), fired


def test_nothing_fires_on_the_clean_file():
    assert check(FIX / "clean") == []


def test_findings_point_at_the_block():
    lines = (FIX / "flawed" / "main.tf").read_text().splitlines()
    for f in check(FIX / "flawed"):
        line = f.where.split(":")[1]
        rtype, name = f.resource.split(".")
        assert lines[int(line) - 1].startswith(f'resource "{rtype}" "{name}"'), f


def test_open_https_is_not_flagged_but_ssh_is():
    sg = [f for f in check(FIX / "flawed") if f.rule == "SG_ADMIN_OPEN"]
    assert [f.detail for f in sg] == ["port 22"]


def test_accepted_findings_keep_their_reason():
    found = {f.rule: f.accepted for f in check(FIX / "accepted")}
    assert found == {"S3_NO_VERSIONING": "Rebuilt from the source every night",
                     "S3_NO_LIFECYCLE": "Emptied by the nightly job"}


def test_a_policy_in_locals_counts():
    assert "S3_TLS_ONLY" not in {f.rule for f in check(FIX / "accepted")}
