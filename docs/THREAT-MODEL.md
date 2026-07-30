# Threat model — the pipeline

STRIDE over **the pipeline itself**, not over PyGoat. PyGoat's vulnerabilities
are the teaching material; they are catalogued in
[`.security/baseline/`](../.security/baseline/) and
[`Solutions/`](../Solutions/solution.md). What this document is about is the
supply chain that builds, scans and publishes it — the part that, if subverted,
would make every finding in that baseline meaningless.

The premise is worth stating plainly: **a security pipeline is a privileged
build system.** It has write access to a container registry, a signing identity,
tokens for third-party services, and it executes third-party code on every push.
It is a more attractive target than the application it scans.

---

## Assets

| Asset | Why an attacker wants it |
| --- | --- |
| `GITHUB_TOKEN` (`packages: write`) | push arbitrary images to GHCR under this repo's name |
| Sigstore OIDC identity (`id-token: write`) | sign arbitrary bytes *as this workflow* |
| The gate's verdict | make a vulnerable build merge, or a clean one fail |
| `.security/baseline/` | accept a real vulnerability by adding one line |
| Optional secrets: `DOCKERHUB_*`, `DEFECTDOJO_*` | lateral movement into other systems |
| Scan reports | the unredacted gitleaks report is a list of live-looking secrets |

## Trust boundaries

```
  contributor ──► pull_request ──► runner (untrusted code, no secrets that matter)
                                     │
                                     ├─ digest-pinned scanner containers
                                     └─ artifacts ──► security gate (no write scopes)

  maintainer ──► push to main ──► runner ──► GHCR + Sigstore  ← the only privileged path
```

Everything a pull request can reach is on the left of that last arrow. `PUBLISH`
is gated on `github.event_name == 'push' && github.ref == 'refs/heads/main'`, and
a fork's `GITHUB_TOKEN` is read-only regardless.

---

## S — Spoofing

**Threat: a forged artefact passed off as a pipeline build.**

* Images are signed with **Cosign keyless**. The identity is the workflow, proven
  by GitHub's OIDC token; there is no private key in the repository, in a secret,
  or on a laptop to steal. `id-token: write` exists on the build job only.
* Signing and attestation are **by digest, never by tag**. Signing a tag leaves a
  window in which the signature covers different bytes than the tag resolves to.
* The signature is **verified in the same run**, pinning both
  `--certificate-identity-regexp` and `--certificate-oidc-issuer`. A signing step
  that merely exits 0 has proven nothing.

**Threat: a scanner container impersonated via a moved tag.** Every scanner is
pinned by digest (`aquasec/trivy@sha256:…`), so a compromised upstream tag cannot
change what runs. See *Tampering* for the limit of this.

**Residual:** anyone who can push to `main` can produce a validly signed image.
That is what branch protection is for — see
[BRANCH-PROTECTION.md](BRANCH-PROTECTION.md).

## T — Tampering

**Threat: a malicious action in the workflow.** Every action is pinned to a full
commit SHA, including `actions/*`. A tag is a mutable pointer; a SHA is not.
Semgrep's `github-actions-mutable-action-tag` rule enforces this on our own
workflow, and baselining that finding was considered and rejected as dishonest.

**Threat: a compromised scanner image.** Digest-pinned, and run in `run:` steps
rather than as marketplace actions, so the trusted surface is one image rather
than an action plus its whole `node_modules`. `make check-pins` fails if any of
the eleven digests drifts from `ci.yml`.

**Threat: the rule set changes under a pinned scanner.**

> This one is real and worth reading twice. Semgrep's rules are **fetched live
> from its registry** at scan time (`--config p/python`, `p/django`,
> `p/owasp-top-ten`). The *image* is digest-pinned; **the rules are not.** A
> Semgrep finding appeared in this repository with no change to the file it
> flagged — `aws-provider-static-credentials` on `provider.tf` — because the
> registry's rule set had moved.

That is benign here, and in fact useful: new rules find old bugs. But the
security property is not what pinning the image suggests. Two consequences are
accepted deliberately:

* the gate can fail on a commit that changed nothing relevant. It is *supposed*
  to; the finding was real and was fixed rather than baselined.
* a registry compromise, or an upstream rule that stops matching, is not
  something a digest protects against. Trivy, Checkov and pip-audit have the same
  property for their vulnerability databases — a scanner with a frozen database
  is a scanner that stops finding new CVEs, so this is a trade-off, not an
  oversight.

**Threat: findings altered between jobs.** Scanning jobs pass
`normalized-*.json` artifacts to the gate. `parse_normalized` **recomputes every
fingerprint from `identity`** rather than trusting the `key` in the file, so a
tampered artifact cannot smuggle a finding past the gate by claiming a baselined
fingerprint.

**Threat: the deployed configuration diverging from the scanned configuration.**
`deploy/k8s/20-configmap-settings.yaml` is generated from
`deploy/overlay/pygoat_deploy_settings.py`, and `make check-overlay` fails on
drift. Without it, DAST would keep passing against settings nobody deploys.

## R — Repudiation

**Threat: an artefact nobody can account for.**

* Images are tagged with the **commit SHA, never `latest`**, so every artefact
  traces to exactly one commit — and the pipeline does not violate the mutable-tag
  ban that `policy/kubernetes.rego` enforces on everyone else.
* An **SBOM** (CycloneDX + SPDX) is attached to every run for 90 days and
  attested to the image digest with Cosign, so "which version of that library was
  in the image we shipped in March?" has an answer.
* The gate writes its verdict, per-scanner counts and every blocking finding to
  the run summary; SARIF goes to code scanning, which keeps history per alert.
* `concurrency` cancels superseded **pull request** runs but never superseded
  pushes to `main`, because those are audit-relevant.

**Residual:** artifact retention is finite (1 day for the image hand-off, 30 for
nightly reports, 90 for SBOMs). Long-term evidence lives in the registry, the
signature transparency log, and code scanning.

## I — Information disclosure

**Threat: leaking the secrets the secret scanner found.** Gitleaks runs twice:
once with `--redact` producing a SARIF that is safe to publish, and once
unredacted producing JSON that is used *only* to compute irreversible
fingerprints. The unredacted file:

* is gitignored;
* is **never uploaded** — the artifact step lists explicit paths, not the
  directory;
* is normalized into fingerprints inside the job that produced it, so only
  hashes cross the job boundary;
* never reaches the baseline in plaintext (`.security/POLICY.md` §1).

**Threat: secrets baked into the published image.** `COPY . /app/` was including
`reports/.gitleaks-unredacted.json` — a plaintext list of secrets — in the image
pushed to GHCR. `.dockerignore` now excludes `reports/`, `deploy/`, `policy/` and
`.security/`. The image went from 4.17 GB to 1.48 GB and its secret findings from
6 to 2 as a side effect.

**Threat: over-broad token scopes.** The workflow grants `contents: read`.
`packages: write` and `id-token: write` are on the build job only;
`security-events: write` on the SARIF upload job only. Nothing else can write
anything.

**Threat: the local triage stack.** DefectDojo publishes on `127.0.0.1` only, and
its keys are generated per machine into gitignored `reports/.defectdojo.env` with
mode 600. Upstream's compose file ships a working `DD_SECRET_KEY` and
`DD_CREDENTIAL_AES_256_KEY`; those values are **public**, and committing them
would put a known encryption key in a security repository. Credentials reach
`defectdojo.py` through the environment, never as arguments, because arguments are
visible in the process table.

**Residual:** PyGoat's own fake credentials are in the repository on purpose —
that is what makes the secret-scanning lesson land. They are catalogued in
`.security/baseline/gitleaks.json` with a justification each.

## D — Denial of service

**Threat: a run that never finishes.** ZAP's spider has a ceiling
(`-m 2`), the DAST teardown runs under `if: always()` so a failed scan cannot
leave a deployment behind, and `concurrency` cancels superseded PR runs.

**Threat: the pipeline made unusable by noise.** This is the failure mode that
actually kills security pipelines, and the baseline exists for it. PyGoat has
2904 accepted findings; a gate that failed on all of them would be switched off
within a week. Only *new* findings block.

**Threat: an unreachable third-party service blocking merges.** Docker Scout and
DefectDojo are both optional, gated on their secrets existing, and DefectDojo is
deliberately **not** a required status check — a triage system being down must not
be able to stop a merge.

**Residual:** Trivy's database is ~100 MB and cached daily; a cache miss plus an
upstream outage will fail the dependency stage. That is correct behaviour (fail
closed), not a bug.

## E — Elevation of privilege

**Threat: pull request code obtaining publish rights.** It cannot. `PUBLISH` is
gated on a push to `main`, and a fork's `GITHUB_TOKEN` is read-only. There is no
`pull_request_target` trigger anywhere in this repository — that trigger runs
untrusted code with the base repository's secrets, and its absence is deliberate.

**Threat: a container escaping into the runner.** Trivy's image scan and Syft
mount `/var/run/docker.sock`, which is root-equivalent on the host. This is
accepted: the alternative is exporting a 1.5 GB tarball for each scanner, the
containers are digest-pinned, and the runner is ephemeral and holds no secrets on
a pull request. It is nonetheless the largest single trust concession in the
pipeline.

**Threat: the deployed workload escalating.** `deploy/k8s/30-deployment.yaml`
drops every capability, runs as UID 10001 with a read-only root filesystem, and
`policy/kubernetes.rego` — with its own unit tests — refuses to let a manifest
regress on any of that. Stage 5 then runs the application under those same
constraints, so "the policy passes but the app cannot start" is caught on a pull
request.

**Residual:** the Terraform module is only ever `validate`d and `plan`ned, never
applied, and there is deliberately no `apply` target. Nothing in this repository
holds AWS credentials; `plan` runs with obvious mock values and `AWS_PROFILE`
emptied so it cannot reach an account even if the runner had them.

---

## Accepted risks, in one place

| Risk | Why it is accepted | How it would be closed |
| --- | --- | --- |
| Semgrep rules fetched live from the registry | a scanner with a frozen rule set stops finding new bugs | vendor the rules and update them deliberately |
| Trivy/Checkov/pip-audit databases not pinned | same trade-off | same, with the same cost |
| `docker.sock` mounted into two scanners | ephemeral runner, no PR secrets, pinned images | export the image to a tarball per scanner |
| EOL Debian base image retained | its CVEs are what the image-scan stage exists to show | rebase onto a supported image (and lose the lesson) |
| 2904 baselined findings | PyGoat is deliberately vulnerable | not applicable — this is the point |
| Docker Scout is a third-party action | no container distribution exists for it | drop Scout, or vendor an equivalent |
| Anyone with push to `main` can produce a signed image | that is what the branch is | branch protection — see [BRANCH-PROTECTION.md](BRANCH-PROTECTION.md) |

The publish path is no longer on that list. It was, while `PUBLISH` had never
been true — signing and the GHCR push are unreachable from a `pull_request` by
design, so nothing could exercise them before the first push to `main`. That push
exercised them and found a real defect: the Cosign steps mounted the runner's
`~/.docker/config.json` into an image that runs as uid 65532 with no `HOME`, so
cosign never read it, authenticated anonymously and GHCR rejected the signature
upload. The push had already succeeded, because it ran on the host. Credentials
are now passed to cosign explicitly, and the push, the signature, the SBOM
attestation and the in-job verification have all run green on `main`.
