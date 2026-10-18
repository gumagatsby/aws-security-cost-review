variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "reviewer_principal_arn" {
  description = "The reviewer's IAM role or account ARN, the only principal allowed to assume the review role"
  type        = string
}

variable "external_id" {
  description = "A value agreed with the reviewer, so a third party can't trick the reviewer into reading this account"
  type        = string
  sensitive   = true
}

variable "role_name" {
  type    = string
  default = "security-cost-review"
}
