locals {
  tls_policy = jsonencode({
    Statement = [{ Effect = "Deny", Action = "s3:*", Condition = { Bool = { "aws:SecureTransport" = "false" } } }]
  })
}

resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "cache" {
  # review: accept S3_NO_VERSIONING Rebuilt from the source every night
  # review: accept S3_NO_LIFECYCLE Emptied by the nightly job
  bucket = "example-cache"
}

resource "aws_s3_bucket_policy" "cache" {
  bucket = aws_s3_bucket.cache.id
  policy = local.tls_policy
}
