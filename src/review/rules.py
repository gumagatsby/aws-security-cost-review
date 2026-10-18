"""The rule catalogue. Each rule names the Well-Architected best practice it checks, why it matters and the fix.

Rules only state what can be read from configuration. Whether a finding matters for a given workload is for the
person reading the report; the severity is a starting point, not a verdict.
"""
from dataclasses import dataclass

WA = "https://docs.aws.amazon.com/wellarchitected/latest/framework/"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pillar: str          # Security, Cost optimization, Reliability
    practice: str        # Well-Architected best practice id
    practice_title: str
    severity: str        # high, medium, low
    why: str
    fix: str
    doc: str             # page name under WA


RULES = {r.id: r for r in [
    # Security
    Rule("S3_PUBLIC_ACCESS", "S3 bucket without Block Public Access", "Security", "SEC03-BP07",
         "Analyze public and cross-account access", "high",
         "Nothing stops a later policy or ACL change from making the bucket public. Block Public Access is the "
         "account- or bucket-level switch that overrides such changes.",
         "Add aws_s3_bucket_public_access_block with all four settings true, or set them once for the account.",
         "sec_permissions_analyze_cross_account.html"),
    Rule("S3_TLS_ONLY", "S3 bucket accepts requests without TLS", "Security", "SEC09-BP02",
         "Enforce encryption in transit", "medium",
         "Without a policy that denies aws:SecureTransport = false, the bucket accepts plain HTTP requests.",
         "Add a bucket policy statement that denies s3:* when aws:SecureTransport is false.",
         "sec_protect_data_transit_encrypt.html"),
    Rule("RDS_UNENCRYPTED", "Database storage not encrypted", "Security", "SEC08-BP02",
         "Enforce encryption at rest", "high",
         "The database, its snapshots and its read replicas are stored unencrypted. Encryption can't be switched "
         "on for an existing instance; it needs a snapshot copy and a restore.",
         "Set storage_encrypted = true, ideally with a customer managed KMS key.",
         "sec_protect_data_rest_encrypt.html"),
    Rule("RDS_PUBLIC", "Database reachable from the internet", "Security", "SEC05-BP01",
         "Create network layers", "high",
         "A publicly accessible database gets a public DNS name; only its security group stands between it and "
         "the internet.",
         "Set publicly_accessible = false and reach it from inside the VPC.",
         "sec_network_protection_create_layers.html"),
    Rule("SG_ADMIN_OPEN", "SSH, RDP or all ports open to the internet", "Security", "SEC05-BP02",
         "Control traffic flow within your network layers", "high",
         "Ports 22 and 3389 open to 0.0.0.0/0 are scanned constantly. Administrative access is better done "
         "through Systems Manager Session Manager, with no inbound port at all.",
         "Remove the rule, or limit it to a known address range; use Session Manager for shell access.",
         "sec_network_protection_layered.html"),
    Rule("IAM_WILDCARD", "IAM policy allows every action on every resource", "Security", "SEC03-BP02",
         "Grant least privilege access", "high",
         "Action \"*\" on Resource \"*\" is administrator access. Whoever holds it can change or delete anything, "
         "including the logs that would show it.",
         "Grant only the actions and resources the role needs; IAM Access Analyzer can generate a policy from "
         "CloudTrail activity.",
         "sec_permissions_least_privileges.html"),
    Rule("PLAINTEXT_SECRET", "Password written into the configuration", "Security", "SEC02-BP03",
         "Store and use secrets securely", "high",
         "A literal password is stored in the repository's history and in the Terraform state.",
         "Use manage_master_user_password = true so RDS keeps it in Secrets Manager, or read it from a secret.",
         "sec_identities_secrets.html"),
    Rule("EBS_UNENCRYPTED", "Disk volume not encrypted", "Security", "SEC08-BP02",
         "Enforce encryption at rest", "medium",
         "The volume and its snapshots are stored unencrypted.",
         "Set encrypted = true, or switch on EBS encryption by default for the region.",
         "sec_protect_data_rest_encrypt.html"),
    Rule("IMDS_V1", "Instance metadata allows IMDSv1", "Security", "SEC06-BP03",
         "Reduce manual management and interactive access", "medium",
         "IMDSv1 answers simple GET requests, so a server-side request forgery bug in the application can read "
         "the instance role's credentials. IMDSv2 requires a session token.",
         "Set metadata_options { http_tokens = \"required\" }.",
         "sec_protect_compute_reduce_manual_management.html"),
    Rule("LAMBDA_URL_OPEN", "Lambda function URL with no authentication", "Security", "SEC03-BP07",
         "Analyze public and cross-account access", "medium",
         "Anyone with the URL can invoke the function, and every invocation is billed.",
         "Use authorization_type = \"AWS_IAM\", with CloudFront Origin Access Control if it serves the public.",
         "sec_permissions_analyze_cross_account.html"),
    Rule("NO_CLOUDTRAIL", "No multi-region CloudTrail trail logging", "Security", "SEC04-BP01",
         "Configure service and application logging", "high",
         "Without a trail, API activity is kept only as 90 days of management events in Event history, "
         "and can't be searched with your other logs or kept for longer.",
         "Create a multi-region trail to a locked S3 bucket, or an organisation trail.",
         "sec_detect_investigate_events_app_service_logging.html"),
    Rule("ROOT_KEYS", "Root user has access keys", "Security", "SEC02-BP02",
         "Use temporary credentials", "high",
         "Root access keys can't be restricted by any policy, and long-lived keys leak.",
         "Delete the root user's access keys and use IAM roles.",
         "sec_identities_unique.html"),
    Rule("ROOT_NO_MFA", "Root user without MFA", "Security", "SEC02-BP01",
         "Use strong sign-in mechanisms", "high",
         "The root user can do anything in the account, including closing it, with only a password.",
         "Turn on MFA for the root user, preferably a hardware key.",
         "sec_identities_enforce_mechanisms.html"),
    Rule("OLD_ACCESS_KEY", "IAM access key older than 90 days", "Security", "SEC02-BP05",
         "Audit and rotate credentials periodically", "medium",
         "Long-lived keys are the most common way AWS credentials leak.",
         "Replace the key with a role, or rotate it and delete the old one.",
         "sec_identities_audit.html"),
    Rule("EBS_DEFAULT_ENCRYPTION_OFF", "EBS encryption by default is off", "Security", "SEC08-BP02",
         "Enforce encryption at rest", "low",
         "New volumes in the region are unencrypted unless each one asks for encryption.",
         "Switch on EBS encryption by default for the region.",
         "sec_protect_data_rest_encrypt.html"),
    # Cost optimization
    Rule("LOG_NO_RETENTION", "Log group kept forever", "Cost optimization", "COST04-BP05",
         "Enforce data retention policies", "low",
         "A log group without a retention period keeps every event, and storage is billed every month.",
         "Set retention_in_days to what the logs are needed for.",
         "cost_decomissioning_resources_data_retention.html"),
    Rule("S3_NO_LIFECYCLE", "S3 bucket without a lifecycle rule", "Cost optimization", "COST04-BP05",
         "Enforce data retention policies", "low",
         "Objects stay in their storage class until someone deletes them.",
         "Add a lifecycle configuration that expires or transitions objects, if the data has a known lifetime.",
         "cost_decomissioning_resources_data_retention.html"),
    Rule("EBS_GP2", "Volume uses gp2", "Cost optimization", "COST06-BP02",
         "Select resource type, size, and number based on data", "low",
         "gp3 costs less per GB than gp2 and gives a baseline of 3,000 IOPS whatever its size.",
         "Change volume_type to gp3; the change happens online.",
         "cost_type_size_number_resources_data.html"),
    Rule("EBS_UNATTACHED", "Volume not attached to anything", "Cost optimization", "COST04-BP03",
         "Decommission resources", "medium",
         "An unattached volume is billed in full every month.",
         "Snapshot it if it might be needed, then delete it.",
         "cost_decomissioning_resources_decommission.html"),
    Rule("EIP_UNUSED", "Elastic IP not associated", "Cost optimization", "COST04-BP03",
         "Decommission resources", "low",
         "Every public IPv4 address is billed by the hour, used or not.",
         "Release the address if nothing needs it.",
         "cost_decomissioning_resources_decommission.html"),
    # Reliability
    Rule("RDS_NO_BACKUP", "Database automated backups switched off", "Reliability", "REL09-BP03",
         "Perform data backup automatically", "high",
         "With a backup retention of 0 there are no automated backups and no point-in-time restore.",
         "Set backup_retention_period to at least 7.",
         "rel_backing_up_data_automated_backups_data.html"),
    Rule("RDS_SINGLE_AZ", "Database in one Availability Zone", "Reliability", "REL10-BP01",
         "Deploy the workload to multiple locations", "low",
         "If its Availability Zone fails, the database is down until it's restored elsewhere. Fine for "
         "development; worth a decision for production.",
         "Set multi_az = true for production databases.",
         "rel_fault_isolation_multiaz_region_system.html"),
    Rule("DDB_NO_PITR", "DynamoDB table without point-in-time recovery", "Reliability", "REL09-BP03",
         "Perform data backup automatically", "medium",
         "Without it, a bad write or delete can't be rolled back to an earlier second.",
         "Add point_in_time_recovery { enabled = true }.",
         "rel_backing_up_data_automated_backups_data.html"),
    Rule("S3_NO_VERSIONING", "S3 bucket without versioning", "Reliability", "REL09-BP01",
         "Identify and back up all data that needs to be backed up, or reproduce the data from sources", "low",
         "An overwritten or deleted object is gone. Not needed for data that can be rebuilt from its source.",
         "Enable versioning, with a lifecycle rule to expire old versions.",
         "rel_backing_up_data_identified_backups_data.html"),
]}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def doc_url(rule: Rule) -> str:
    return WA + rule.doc
