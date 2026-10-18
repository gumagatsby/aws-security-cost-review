output "role_arn" {
  description = "Give this to the reviewer, with the external id"
  value       = aws_iam_role.review.arn
}
