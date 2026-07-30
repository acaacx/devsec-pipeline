output "repository_url" {
  description = "Registry URL to push to. Unknown until apply, so it shows as (known after apply) in a plan."
  value       = aws_ecr_repository.app.repository_url
}

output "repository_arn" {
  description = "ARN of the repository, for wiring into an IAM policy or a deploy role."
  value       = aws_ecr_repository.app.arn
}

output "image_tag_mutability" {
  description = "Surfaced as an output so the setting is visible in plan output and in CI logs, not just in the source."
  value       = aws_ecr_repository.app.image_tag_mutability
}
