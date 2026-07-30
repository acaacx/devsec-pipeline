# The registry side of the supply chain.
#
# The pipeline already builds, signs and attests images. That is worth nothing if
# the registry lets a tag be moved after the fact, so the three properties below
# are what make a signature meaningful rather than decorative:
#
#   * immutable tags     - a tag cannot be repointed, so "the image we signed" and
#                          "the image we deploy" cannot drift apart
#   * scan on push       - the registry re-scans independently of CI, which catches
#                          CVEs published after the build
#   * encryption at rest - KMS rather than the default AES256
resource "aws_ecr_repository" "app" {
  name = var.repository_name

  # The single most important setting here. With MUTABLE tags, `:v1.2.3` can be
  # made to point at different content later, which defeats both the Cosign
  # signature and any audit trail built on tags.
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    # KMS with the AWS-managed ECR key. A customer-managed key would be stronger
    # still, but creating one needs a key policy naming the account principal,
    # which requires an aws_caller_identity data source - and that needs real
    # credentials, which would break the credential-free `plan` this module is
    # built around. The trade-off is recorded rather than silently taken.
    encryption_type = "KMS"
  }

  # Deleting a repository that still holds images should be a deliberate act, not
  # a side effect of `terraform destroy`.
  force_delete = false
}

# Untagged images accumulate on every rebuild and are pure attack surface: they
# are still pullable by digest and still contain whatever the build put in them.
# Tagged images are capped as well, so the registry does not grow without bound.
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.untagged_image_expiry_days
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Retain a bounded number of tagged images"
        selection = {
          tagStatus      = "tagged"
          tagPatternList = ["*"]
          countType      = "imageCountMoreThan"
          countNumber    = var.tagged_image_retention_count
        }
        action = { type = "expire" }
      },
    ]
  })
}

# Deliberately no aws_ecr_repository_policy.
#
# An earlier revision of this module carried an explicit "deny anonymous access"
# statement. It was removed rather than baselined, and the reasoning is worth
# recording because the removal looks like a weakening and is not:
#
#   * ECR repositories are private on creation. Anonymous access is not possible
#     unless a repository policy explicitly Allows it, so the deny statement was
#     not closing an open door - it was restating the default.
#   * Expressing "deny anonymous" requires Principal = "*". Trivy's AVD-AWS-0032
#     reports any wildcard principal as public access without distinguishing
#     Effect Allow from Effect Deny, so the statement produced a permanent HIGH
#     finding for a control that changed nothing.
#   * Its only real value was guarding against a future over-broad policy - but a
#     future edit able to add that policy could equally delete this statement.
#
# Access is therefore governed by IAM, which is where ECR authorization belongs.
# Grant pull rights to a specific deploy role rather than reopening this file.
