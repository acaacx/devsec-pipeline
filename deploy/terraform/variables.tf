variable "aws_region" {
  description = "Region for the registry. Only used to configure the provider; no resource here is region-specific beyond that."
  type        = string
  default     = "eu-west-2"
}

variable "repository_name" {
  description = "ECR repository name. Matches the GHCR repository so an image has the same identity in both registries."
  type        = string
  default     = "devsec-pipeline"

  validation {
    # ECR rejects names outside this pattern with an opaque API error at apply
    # time. Failing in `validate` instead is the whole point of having a
    # validation block.
    condition     = can(regex("^[a-z0-9][a-z0-9._/-]{1,255}$", var.repository_name))
    error_message = "repository_name must be lowercase and start with a letter or digit (ECR naming rules)."
  }
}

variable "untagged_image_expiry_days" {
  description = "Days before an untagged image is expired by the lifecycle policy."
  type        = number
  default     = 7

  validation {
    condition     = var.untagged_image_expiry_days >= 1 && var.untagged_image_expiry_days <= 3650
    error_message = "untagged_image_expiry_days must be between 1 and 3650."
  }
}

variable "tagged_image_retention_count" {
  description = "Number of tagged images to retain. Older ones are expired."
  type        = number
  default     = 30

  validation {
    condition     = var.tagged_image_retention_count >= 1
    error_message = "tagged_image_retention_count must be at least 1."
  }
}

variable "tags" {
  description = "Tags applied to every resource via the provider's default_tags."
  type        = map(string)
  default = {
    Project   = "devsec-pipeline"
    ManagedBy = "terraform"
    # Named explicitly so nobody mistakes a PyGoat registry for something that
    # belongs in a production account.
    Workload = "deliberately-vulnerable-demo"
  }
}
