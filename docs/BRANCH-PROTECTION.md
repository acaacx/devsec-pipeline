# Branch protection

A gate that a merge can walk around is decoration. This is the repository
configuration that makes `main` actually depend on the pipeline, and the
reasoning for each setting.

None of it lives in the repository — branch protection is server-side state, not
a file — so this document is the source of truth for what `main` should be
configured to, and the `gh` recipe at the bottom applies it.

---

## The one required status check

```
Security gate
```

That is deliberately the only one, and it is sufficient:

```yaml
security-gate:
  needs: [code-scan, dependency-scan, build-and-package, provision-scan, dast]
  if: always()
```

Because the gate runs under `if: always()` and fails when any upstream stage did
not succeed, requiring it transitively requires all five stages. A stage that
fails, is cancelled, or is skipped because its dependency failed all produce a
red gate — see the completeness check in
[`ci.yml`](../.github/workflows/ci.yml).

Adding the five stages as required checks as well is harmless but redundant, and
it makes the required-checks list something that has to be edited every time the
pipeline gains a stage.

### What must *not* be required

| Check | Why not |
| --- | --- |
| `Code scanning upload` | publishing evidence is not gating. A SARIF upload failing — a service blip, a size limit — must not block a merge that the gate passed. |
| `Triage - DefectDojo import` | a triage system being unreachable must not be able to stop a merge. It is optional and skips entirely without its secrets. |
| `Nightly - …` | those jobs never run on a pull request, so requiring them would block every merge forever. |

That last row is the general trap: **a required check that does not run on every
pull request blocks all merges, silently and permanently.** GitHub waits for a
status that will never arrive. Anything conditional — `paths:` filters,
`if:` guards on secrets, scheduled workflows — must stay out of the required
list.

## Recommended settings for `main`

| Setting | Value | Why |
| --- | --- | --- |
| Require status checks | `Security gate` | the gate is the merge criterion |
| Require branches up to date before merging | on | otherwise the gate's verdict is about a tree nobody is merging; two independently-clean branches can merge into a broken one |
| Require a pull request before merging | on | the gate only evaluates PR and `main` runs |
| Required approving reviews | 1 | `.security/baseline/` is a file where one line accepts a real vulnerability; that deserves a second pair of eyes |
| Dismiss stale approvals on new commits | on | an approval is of a diff, not of a branch name |
| Require conversation resolution | on | a raised concern should not merge unanswered |
| Require linear history | on | every artefact is tagged with one commit SHA; a merge commit that was never built is a gap in that chain |
| Block force pushes | on | history rewriting is how an accepted-then-reverted finding disappears |
| Block deletions | on | — |
| Include administrators | on | a rule the owner can step over is a suggestion. Turn it off only to unblock a genuine emergency, and turn it back on afterwards (`.security/POLICY.md` §3(c) covers emergency bypass) |
| Require signed commits | optional | the pipeline signs *artefacts* with Cosign keyless, which is the property that matters for what gets deployed. Commit signing is a different guarantee about a different asset |

This repository is public, so branch protection and required status checks are
available on the free plan.

## Applying it

```bash
gh api -X PUT repos/:owner/:repo/branches/main/protection \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["Security gate"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false
  },
  "required_linear_history": true,
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "restrictions": null
}
JSON
```

`restrictions: null` is required by the API — omitting it is an error, and a
non-null value would restrict *who* can push, which is a separate decision.

Verify what is actually in force, rather than what you meant to set:

```bash
gh api repos/:owner/:repo/branches/main/protection \
  --jq '{checks: .required_status_checks.contexts,
         strict: .required_status_checks.strict,
         admins: .enforce_admins.enabled,
         reviews: .required_pull_request_reviews.required_approving_review_count,
         linear: .required_linear_history.enabled,
         force_push: .allow_force_pushes.enabled}'
```

### A one-person repository

With `required_approving_review_count: 1` and `enforce_admins: true`, a solo
maintainer cannot merge their own pull request. That is a real cost, and there
are exactly two honest resolutions: drop the review requirement and say so, or
keep it and accept that merging needs a second person. Setting it and then
disabling admin enforcement to work around it is the dishonest third option —
the branch looks protected and is not.

## What branch protection does *not* cover

* **The baseline.** Nothing prevents a reviewer approving a pull request that
  adds a baseline entry for a genuine vulnerability. The controls there are
  social and documentary: `.security/POLICY.md` requires a written
  justification, `default_justification()` emits `REVIEW REQUIRED` for every
  Stage 4 scanner so an unjustified entry is loud, and exceptions for the
  pipeline's own code need a compensating control and an expiry date. A
  `CODEOWNERS` entry for `.security/` is the next step if this repository ever
  gains more than one maintainer.
* **Tags and releases.** Protected branches say nothing about tags; a tag
  protection rule is a separate object.
* **The publish path.** `PUBLISH` is gated on
  `github.event_name == 'push' && github.ref == 'refs/heads/main'` inside the
  workflow. Branch protection controls what reaches `main`; the workflow controls
  what `main` is allowed to do. Both are needed, and neither substitutes for the
  other.
* **Fork pull requests.** A fork's `GITHUB_TOKEN` is read-only and cannot upload
  SARIF, so `Code scanning upload` will fail on fork PRs. That is another reason
  it is not a required check.
