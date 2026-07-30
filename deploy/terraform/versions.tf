# Provider versions are pinned with `~>` rather than left open. An unpinned
# provider means `terraform init` can change infrastructure behaviour between two
# runs of identical code, which is the same supply-chain problem as a mutable
# container tag - and the same reason every action in this pipeline carries a
# commit SHA.
#
# There is deliberately no `backend` block. This module is only ever validated and
# planned in CI, never applied, so there is no state to store. Adding a backend
# would make `terraform init` require credentials and break the credential-free
# validation this module is designed for.
terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
