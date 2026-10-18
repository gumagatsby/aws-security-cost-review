"""python -m review terraform PATH | python -m review account --regions eu-west-2 [--role-arn ARN --external-id ID]"""
import argparse
import sys
from pathlib import Path

import boto3

from . import explain, live, report, tf
from .findings import ordered
from .rules import RULES, SEVERITY_ORDER


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="review", description="AWS security and cost review")
    sub = ap.add_subparsers(dest="scope", required=True)
    t = sub.add_parser("terraform", help="review Terraform files without touching AWS")
    t.add_argument("path", type=Path)
    a = sub.add_parser("account", help="review a live account through read-only calls")
    a.add_argument("--regions", default="eu-west-2", help="comma-separated")
    a.add_argument("--role-arn", help="the client's review role; omit to use your own credentials")
    a.add_argument("--external-id")
    a.add_argument("--profile")
    for p in (t, a):
        p.add_argument("--out", type=Path, default=Path("out"))
        p.add_argument("--explain", action="store_true", help="have Amazon Nova Lite write the summary")
        p.add_argument("--model-region", default="eu-west-2")
        p.add_argument("--fail-on", choices=["high", "medium", "low"],
                       help="exit 1 if an open finding is at least this severe, for CI")
    args = ap.parse_args(argv)

    if args.scope == "terraform":
        findings, target, skipped = tf.check(args.path), str(args.path), []
    else:
        session = live.session_for(args.role_arn, args.external_id, args.profile)
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
        account = session.client("sts").get_caller_identity()["Account"]
        findings, skipped = live.check(session, regions)
        target = f"account {account}, {', '.join(regions)}"
    findings = ordered(findings)

    bedrock = boto3.client("bedrock-runtime", region_name=args.model_region) if args.explain else None
    summary, source = explain.summarise(findings, bedrock)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.md").write_text(report.markdown(findings, args.scope, target, summary, source, skipped))
    (args.out / "findings.json").write_text(report.as_json(findings, args.scope, target, source, skipped))
    print(f"{len(findings)} findings ({sum(1 for f in findings if f.accepted)} accepted); "
          f"{len(skipped)} checks refused; report in {args.out / 'report.md'}; summary: {source}")

    if args.fail_on:
        bar = SEVERITY_ORDER[args.fail_on]
        if any(not f.accepted and SEVERITY_ORDER[RULES[f.rule].severity] <= bar for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
