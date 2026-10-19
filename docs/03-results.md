# Results

Run on 18 October 2026.

## The rules against a sample written to break them (N1)

`tests/fixtures/flawed/main.tf` breaks every rule that can be read from Terraform. Each of those 17 rules fires exactly once on it, and none fires on `tests/fixtures/clean/main.tf`, which sets the same resources up correctly. The live-account checks are tested against a mocked AWS account with moto, except two: root access keys, and Lambda function URLs read from a live account. The Lambda rule is tested on Terraform; the root key check reads one field of the IAM account summary. The full report on the flawed sample is in [examples/flawed-terraform](../examples/flawed-terraform/report.md).

## This portfolio's own Terraform (N6)

50 Terraform files across the five projects that use Terraform. Projects 04, 05 and 07 have none.

| Project | Finding | Severity | Verdict |
|---|---|---|---|
| 01 Serverless sales data pipeline | The Terraform state bucket accepts requests without TLS | Medium | Real. The data buckets deny non-TLS requests; the state bucket, made by the bootstrap stack, doesn't |
| 01 Serverless sales data pipeline | The audit table has no point-in-time recovery | Medium | Deliberate: point-in-time recovery is billed and the table can be rebuilt from S3. Now marked as accepted in the code |
| 01 Serverless sales data pipeline | The data buckets have no versioning | Low | Real. Whether it matters depends on whether their contents can be rebuilt |
| 03 Hybrid migration and disaster recovery | The database runs in one Availability Zone | Low | Deliberate: disaster recovery is the Ireland pilot light, not a standby in London. Now marked as accepted in the code |
| 06 Edge analytics on AWS | The buckets have no versioning | Low | Real. Whether it matters depends on whether their contents can be rebuilt |

The first run also reported 02's CloudTrail bucket as accepting non-TLS requests. That was the tool's mistake: the bucket's policy is built in a `locals` block, which it didn't follow. It does now, and a test covers it.

## This portfolio's own AWS account (N5, N6)

Three regions: London, Ireland and N. Virginia. 16 findings: 3 high, 2 medium, 11 low. The report, with the account number masked, is in [examples/own-account](../examples/own-account/report.md).

| Finding | Where | Note |
|---|---|---|
| No multi-region CloudTrail trail logging | All three regions | Real: no trail exists in any of them. Event history keeps 90 days of management events, and nothing longer |
| The state bucket accepts requests without TLS | London | The same gap the Terraform review found in project 01 |
| The audit table has no point-in-time recovery | London | The same deliberate choice as in project 01's Terraform |
| Log groups kept forever | 5 log groups | Low |
| EBS encryption by default is off | All three regions | Low. No volumes exist in London |
| Buckets without versioning | Project 01's 3 data buckets | Low, as in its Terraform |

The report lists the three Lambda checks as not checked, and uses the plain summary built from the rules rather than the model-written one. It says so in both places.

## What's open

- Fix the state bucket's TLS policy in project 01. Its bootstrap stack needs a change and an apply, so it's left for when that stack is next changed.
- Run the model-written summary and record whether it passes its check.
