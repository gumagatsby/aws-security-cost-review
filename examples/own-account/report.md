# AWS security and cost review

**Reviewed:** account <account>, eu-west-2, eu-west-1, us-east-1  
**Date:** 18 October 2026  
**Rules:** 24, each mapped to an AWS Well-Architected best practice

## Summary

16 open findings: 3 high, 2 medium, 11 low. Start with: No multi-region CloudTrail trail logging [1, 2, 3].

*Summary written from the rules alone.*

| Pillar | High | Medium | Low |
|---|---|---|---|
| Security | 3 | 1 | 3 |
| Cost optimization | 0 | 0 | 5 |
| Reliability | 0 | 1 | 3 |

## Findings

### 1. No multi-region CloudTrail trail logging

**High** · Security · `cloudtrail` · eu-west-1

**Why it matters:** Without a trail, API activity is kept only as 90 days of management events in Event history, and can't be searched with your other logs or kept for longer.

**Fix:** Create a multi-region trail to a locked S3 bucket, or an organisation trail.

**Best practice:** [SEC04-BP01 Configure service and application logging](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_detect_investigate_events_app_service_logging.html)

### 2. No multi-region CloudTrail trail logging

**High** · Security · `cloudtrail` · eu-west-2

**Why it matters:** Without a trail, API activity is kept only as 90 days of management events in Event history, and can't be searched with your other logs or kept for longer.

**Fix:** Create a multi-region trail to a locked S3 bucket, or an organisation trail.

**Best practice:** [SEC04-BP01 Configure service and application logging](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_detect_investigate_events_app_service_logging.html)

### 3. No multi-region CloudTrail trail logging

**High** · Security · `cloudtrail` · us-east-1

**Why it matters:** Without a trail, API activity is kept only as 90 days of management events in Event history, and can't be searched with your other logs or kept for longer.

**Fix:** Create a multi-region trail to a locked S3 bucket, or an organisation trail.

**Best practice:** [SEC04-BP01 Configure service and application logging](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_detect_investigate_events_app_service_logging.html)

### 4. DynamoDB table without point-in-time recovery

**Medium** · Reliability · `ssp-load-audit` · eu-west-2

**Why it matters:** Without it, a bad write or delete can't be rolled back to an earlier second.

**Fix:** Add point_in_time_recovery { enabled = true }.

**Best practice:** [REL09-BP03 Perform data backup automatically](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_automated_backups_data.html)

### 5. S3 bucket accepts requests without TLS

**Medium** · Security · `arn:aws:s3:::tfstate-<account>-eu-west-2` · eu-west-2

**Why it matters:** Without a policy that denies aws:SecureTransport = false, the bucket accepts plain HTTP requests.

**Fix:** Add a bucket policy statement that denies s3:* when aws:SecureTransport is false.

**Best practice:** [SEC09-BP02 Enforce encryption in transit](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_transit_encrypt.html)

### 6. EBS encryption by default is off

**Low** · Security · `eu-west-1` · eu-west-1

**Why it matters:** New volumes in the region are unencrypted unless each one asks for encryption.

**Fix:** Switch on EBS encryption by default for the region.

**Best practice:** [SEC08-BP02 Enforce encryption at rest](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_rest_encrypt.html)

### 7. EBS encryption by default is off

**Low** · Security · `eu-west-2` · eu-west-2

**Why it matters:** New volumes in the region are unencrypted unless each one asks for encryption.

**Fix:** Switch on EBS encryption by default for the region.

**Best practice:** [SEC08-BP02 Enforce encryption at rest](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_rest_encrypt.html)

### 8. EBS encryption by default is off

**Low** · Security · `us-east-1` · us-east-1

**Why it matters:** New volumes in the region are unencrypted unless each one asks for encryption.

**Fix:** Switch on EBS encryption by default for the region.

**Best practice:** [SEC08-BP02 Enforce encryption at rest](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_rest_encrypt.html)

### 9. Log group kept forever

**Low** · Cost optimization · `/aws-glue/jobs/edge-analytics-role/edge-analytics-glue/error` · eu-west-2

**Why it matters:** A log group without a retention period keeps every event, and storage is billed every month.

**Fix:** Set retention_in_days to what the logs are needed for.

**Best practice:** [COST04-BP05 Enforce data retention policies](https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_decomissioning_resources_data_retention.html)

### 10. Log group kept forever

**Low** · Cost optimization · `/aws-glue/jobs/edge-analytics-role/edge-analytics-glue/output` · eu-west-2

**Why it matters:** A log group without a retention period keeps every event, and storage is billed every month.

**Fix:** Set retention_in_days to what the logs are needed for.

**Best practice:** [COST04-BP05 Enforce data retention policies](https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_decomissioning_resources_data_retention.html)

### 11. Log group kept forever

**Low** · Cost optimization · `/aws-glue/jobs/error` · eu-west-2

**Why it matters:** A log group without a retention period keeps every event, and storage is billed every month.

**Fix:** Set retention_in_days to what the logs are needed for.

**Best practice:** [COST04-BP05 Enforce data retention policies](https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_decomissioning_resources_data_retention.html)

### 12. Log group kept forever

**Low** · Cost optimization · `/aws-glue/jobs/logs-v2` · eu-west-2

**Why it matters:** A log group without a retention period keeps every event, and storage is billed every month.

**Fix:** Set retention_in_days to what the logs are needed for.

**Best practice:** [COST04-BP05 Enforce data retention policies](https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_decomissioning_resources_data_retention.html)

### 13. Log group kept forever

**Low** · Cost optimization · `/aws-glue/jobs/output` · eu-west-2

**Why it matters:** A log group without a retention period keeps every event, and storage is billed every month.

**Fix:** Set retention_in_days to what the logs are needed for.

**Best practice:** [COST04-BP05 Enforce data retention policies](https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_decomissioning_resources_data_retention.html)

### 14. S3 bucket without versioning

**Low** · Reliability · `arn:aws:s3:::ssp-athena-<account>-eu-west-2` · eu-west-2

**Why it matters:** An overwritten or deleted object is gone. Not needed for data that can be rebuilt from its source.

**Fix:** Enable versioning, with a lifecycle rule to expire old versions.

**Best practice:** [REL09-BP01 Identify and back up all data that needs to be backed up, or reproduce the data from sources](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_identified_backups_data.html)

### 15. S3 bucket without versioning

**Low** · Reliability · `arn:aws:s3:::ssp-curated-<account>-eu-west-2` · eu-west-2

**Why it matters:** An overwritten or deleted object is gone. Not needed for data that can be rebuilt from its source.

**Fix:** Enable versioning, with a lifecycle rule to expire old versions.

**Best practice:** [REL09-BP01 Identify and back up all data that needs to be backed up, or reproduce the data from sources](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_identified_backups_data.html)

### 16. S3 bucket without versioning

**Low** · Reliability · `arn:aws:s3:::ssp-raw-<account>-eu-west-2` · eu-west-2

**Why it matters:** An overwritten or deleted object is gone. Not needed for data that can be rebuilt from its source.

**Fix:** Enable versioning, with a lifecycle rule to expire old versions.

**Best practice:** [REL09-BP01 Identify and back up all data that needs to be backed up, or reproduce the data from sources](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_identified_backups_data.html)

## What this review didn't cover

Read from the account through read-only API calls, in the regions listed. Only the rules below are checked; this isn't a full Well-Architected review, which also covers how the team operates.

These checks were refused by the account, usually by a service control policy or a missing permission, so nothing is known about them:

- Lambda in eu-west-2: AccessDeniedException
- Lambda in eu-west-1: AccessDeniedException
- Lambda in us-east-1: AccessDeniedException
