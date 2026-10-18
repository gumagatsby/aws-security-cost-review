# AWS security and cost review

**Reviewed:** tests/fixtures/flawed, a sample written to break every rule  
**Date:** 18 October 2026  
**Rules:** 24, each mapped to an AWS Well-Architected best practice

## Summary

17 open findings: 7 high, 5 medium, 5 low. Start with: IAM policy allows every action on every resource [1]; Password written into the configuration [2]; Database automated backups switched off [3].

*Summary written from the rules alone.*

| Pillar | High | Medium | Low |
|---|---|---|---|
| Security | 6 | 4 | 0 |
| Cost optimization | 0 | 0 | 3 |
| Reliability | 1 | 1 | 2 |

## Findings

### 1. IAM policy allows every action on every resource

**High** · Security · `aws_iam_role_policy.admin` · main.tf:33

**Why it matters:** Action "*" on Resource "*" is administrator access. Whoever holds it can change or delete anything, including the logs that would show it.

**Fix:** Grant only the actions and resources the role needs; IAM Access Analyzer can generate a policy from CloudTrail activity.

**Best practice:** [SEC03-BP02 Grant least privilege access](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_permissions_least_privileges.html)

### 2. Password written into the configuration

**High** · Security · `aws_db_instance.orders` · main.tf:7 · password

**Why it matters:** A literal password is stored in the repository's history and in the Terraform state.

**Fix:** Use manage_master_user_password = true so RDS keeps it in Secrets Manager, or read it from a secret.

**Best practice:** [SEC02-BP03 Store and use secrets securely](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_secrets.html)

### 3. Database automated backups switched off

**High** · Reliability · `aws_db_instance.orders` · main.tf:7

**Why it matters:** With a backup retention of 0 there are no automated backups and no point-in-time restore.

**Fix:** Set backup_retention_period to at least 7.

**Best practice:** [REL09-BP03 Perform data backup automatically](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_automated_backups_data.html)

### 4. Database reachable from the internet

**High** · Security · `aws_db_instance.orders` · main.tf:7

**Why it matters:** A publicly accessible database gets a public DNS name; only its security group stands between it and the internet.

**Fix:** Set publicly_accessible = false and reach it from inside the VPC.

**Best practice:** [SEC05-BP01 Create network layers](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_network_protection_create_layers.html)

### 5. Database storage not encrypted

**High** · Security · `aws_db_instance.orders` · main.tf:7

**Why it matters:** The database, its snapshots and its read replicas are stored unencrypted. Encryption can't be switched on for an existing instance; it needs a snapshot copy and a restore.

**Fix:** Set storage_encrypted = true, ideally with a customer managed KMS key.

**Best practice:** [SEC08-BP02 Enforce encryption at rest](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_rest_encrypt.html)

### 6. S3 bucket without Block Public Access

**High** · Security · `aws_s3_bucket.uploads` · main.tf:3

**Why it matters:** Nothing stops a later policy or ACL change from making the bucket public. Block Public Access is the account- or bucket-level switch that overrides such changes.

**Fix:** Add aws_s3_bucket_public_access_block with all four settings true, or set them once for the account.

**Best practice:** [SEC03-BP07 Analyze public and cross-account access](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_permissions_analyze_cross_account.html)

### 7. SSH, RDP or all ports open to the internet

**High** · Security · `aws_security_group.web` · main.tf:17 · port 22

**Why it matters:** Ports 22 and 3389 open to 0.0.0.0/0 are scanned constantly. Administrative access is better done through Systems Manager Session Manager, with no inbound port at all.

**Fix:** Remove the rule, or limit it to a known address range; use Session Manager for shell access.

**Best practice:** [SEC05-BP02 Control traffic flow within your network layers](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_network_protection_layered.html)

### 8. DynamoDB table without point-in-time recovery

**Medium** · Reliability · `aws_dynamodb_table.sessions` · main.tf:54

**Why it matters:** Without it, a bad write or delete can't be rolled back to an earlier second.

**Fix:** Add point_in_time_recovery { enabled = true }.

**Best practice:** [REL09-BP03 Perform data backup automatically](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_automated_backups_data.html)

### 9. Disk volume not encrypted

**Medium** · Security · `aws_instance.app` · main.tf:41 · root or attached volume

**Why it matters:** The volume and its snapshots are stored unencrypted.

**Fix:** Set encrypted = true, or switch on EBS encryption by default for the region.

**Best practice:** [SEC08-BP02 Enforce encryption at rest](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_rest_encrypt.html)

### 10. Instance metadata allows IMDSv1

**Medium** · Security · `aws_instance.app` · main.tf:41

**Why it matters:** IMDSv1 answers simple GET requests, so a server-side request forgery bug in the application can read the instance role's credentials. IMDSv2 requires a session token.

**Fix:** Set metadata_options { http_tokens = "required" }.

**Best practice:** [SEC06-BP03 Reduce manual management and interactive access](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_compute_reduce_manual_management.html)

### 11. Lambda function URL with no authentication

**Medium** · Security · `aws_lambda_function_url.api` · main.tf:49

**Why it matters:** Anyone with the URL can invoke the function, and every invocation is billed.

**Fix:** Use authorization_type = "AWS_IAM", with CloudFront Origin Access Control if it serves the public.

**Best practice:** [SEC03-BP07 Analyze public and cross-account access](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_permissions_analyze_cross_account.html)

### 12. S3 bucket accepts requests without TLS

**Medium** · Security · `aws_s3_bucket.uploads` · main.tf:3

**Why it matters:** Without a policy that denies aws:SecureTransport = false, the bucket accepts plain HTTP requests.

**Fix:** Add a bucket policy statement that denies s3:* when aws:SecureTransport is false.

**Best practice:** [SEC09-BP02 Enforce encryption in transit](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_transit_encrypt.html)

### 13. Volume uses gp2

**Low** · Cost optimization · `aws_instance.app` · main.tf:41

**Why it matters:** gp3 costs less per GB than gp2 and gives a baseline of 3,000 IOPS whatever its size.

**Fix:** Change volume_type to gp3; the change happens online.

**Best practice:** [COST06-BP02 Select resource type, size, and number based on data](https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_type_size_number_resources_data.html)

### 14. Log group kept forever

**Low** · Cost optimization · `aws_cloudwatch_log_group.app` · main.tf:64

**Why it matters:** A log group without a retention period keeps every event, and storage is billed every month.

**Fix:** Set retention_in_days to what the logs are needed for.

**Best practice:** [COST04-BP05 Enforce data retention policies](https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_decomissioning_resources_data_retention.html)

### 15. Database in one Availability Zone

**Low** · Reliability · `aws_db_instance.orders` · main.tf:7

**Why it matters:** If its Availability Zone fails, the database is down until it's restored elsewhere. Fine for development; worth a decision for production.

**Fix:** Set multi_az = true for production databases.

**Best practice:** [REL10-BP01 Deploy the workload to multiple locations](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_fault_isolation_multiaz_region_system.html)

### 16. S3 bucket without a lifecycle rule

**Low** · Cost optimization · `aws_s3_bucket.uploads` · main.tf:3

**Why it matters:** Objects stay in their storage class until someone deletes them.

**Fix:** Add a lifecycle configuration that expires or transitions objects, if the data has a known lifetime.

**Best practice:** [COST04-BP05 Enforce data retention policies](https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_decomissioning_resources_data_retention.html)

### 17. S3 bucket without versioning

**Low** · Reliability · `aws_s3_bucket.uploads` · main.tf:3

**Why it matters:** An overwritten or deleted object is gone. Not needed for data that can be rebuilt from its source.

**Fix:** Enable versioning, with a lifecycle rule to expire old versions.

**Best practice:** [REL09-BP01 Identify and back up all data that needs to be backed up, or reproduce the data from sources](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_identified_backups_data.html)

## What this review didn't cover

Read from the Terraform files alone. Values set by variables or other resources can't be known without a plan, so a rule fires only on what a file states or on a setting that's missing. Resources created by modules from a registry aren't read.
