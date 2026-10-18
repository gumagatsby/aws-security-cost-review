# The role a client creates in their own account so the review can read it. It can read configuration only:
# the AWS managed SecurityAudit policy covers every call the review makes, and nothing that changes a resource.
resource "aws_iam_role" "review" {
  name                 = var.role_name
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.reviewer_principal_arn }
      Action    = "sts:AssumeRole"
      # The external id stops the confused deputy problem: only a request carrying the agreed value is accepted.
      Condition = { StringEquals = { "sts:ExternalId" = var.external_id } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.review.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}
