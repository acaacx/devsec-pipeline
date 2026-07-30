# The provider is configured to be plannable with no AWS credentials present.
#
# This module exists to be *scanned*, not applied - it is the IaC target for
# Checkov, Trivy config and the OPA policies. CI must therefore be able to run
# `terraform init`, `validate` and `plan` on a runner that has no AWS account
# attached to it and no ability to obtain one. The three skip_* flags suppress
# the provider's start-up calls to STS and the EC2 instance metadata service,
# which are the only things that would otherwise require real credentials for a
# create-only plan.
#
# The provider still requires credential fields to be populated even when every
# call that would use them is skipped, so placeholder values have to come from
# somewhere. They deliberately do not come from here.
#
# An earlier revision set `access_key`/`secret_key` inline. Semgrep's
# aws-provider-static-credentials rule flagged it, correctly: a rule that fires
# on hardcoded provider credentials cannot be expected to distinguish a
# placeholder from a live key, and a reader cannot either. Baselining it would
# have taught exactly the habit this pipeline exists to discourage, so the
# credentials moved to AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in the
# environment - set to obvious mock values by `make tf-validate` and by the
# equivalent step in .github/workflows/ci.yml, and by nothing else.
#
# Anyone actually applying this module should supply credentials through role
# assumption or OIDC. There is no state backend configured, so `apply` from here
# would produce untracked infrastructure - which is the second reason not to.
provider "aws" {
  region = var.aws_region

  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true

  default_tags {
    tags = var.tags
  }
}
