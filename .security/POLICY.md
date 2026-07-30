# Security gate policy

The application this pipeline scans is [PyGoat](https://github.com/adeyosemanputra/pygoat),
a **deliberately vulnerable** Django application, vendored here unmodified as a
test fixture. That single fact drives every decision below.

A naive gate — *fail the build on any critical finding* — would make this
pipeline permanently red. A permanently red pipeline is not a strict pipeline; it
is an ignored one. The moment every run is red, nobody can tell the difference
between "this app has the vulnerabilities it is supposed to have" and "someone
just introduced a new one." Disabling the gates instead is worse: you get green
builds that prove nothing.

So the gate is not tuned by severity alone. It is tuned by **novelty**.

---

## 1. The baseline mechanism

`.security/baseline/<scanner>.json` holds every finding we have seen and
accepted, one file per scanner. The gate fails only on findings whose
fingerprint is **absent** from the baseline.

| Finding is… | Gate verdict |
| --- | --- |
| In the baseline | Accepted, reported as "baselined" |
| Not in the baseline, severity at or above the scanner's threshold | **Blocks the build** |
| Not in the baseline, below threshold | Reported as new, does not block |
| In the baseline but no longer observed | Reported as stale drift; run `make baseline-update` |

That last row matters more than it looks. A shrinking baseline is the only
evidence that the pipeline is improving rather than merely quiet.

### Fingerprints are location-independent

A baseline keyed on file-and-line would break on the first reformat, dumping
hundreds of "new" findings into the gate and training everyone to bypass it. So
each fingerprint is `sha256(scanner | rule | path | identity)` truncated to 20
hex characters, where `identity` deliberately **excludes** line numbers:

| Scanner | `identity` is derived from |
| --- | --- |
| Bandit | hash of the flagged source snippet, whitespace-collapsed |
| Semgrep | hash of the matched source text (falls back to the message) |
| Gitleaks | `sha256` of the secret itself |
| pip-audit | package name + exact version + advisory ID |
| Trivy (deps) | package name + exact version + CVE ID |
| Trivy (secrets) | hash of the matched text |
| Trivy (config/misconfig) | check ID + message |
| ZAP | plugin ID + alert reference — **not** the URLs it was observed at |

Two consequences worth stating plainly:

- **Moving vulnerable code does not create a new finding.** Editing it does. That
  is the correct behaviour: the code changed, so the acceptance should be
  re-reviewed.
- **Bumping a dependency invalidates its baseline entries**, because the version
  is part of the identity. Upgrading `Django 4.1.7` to a still-vulnerable
  `4.1.8` re-blocks the build rather than silently inheriting the old
  acceptance.

The same rule is why two things that *look* like part of a finding are excluded.
A Trivy image target is named `<image-ref> (<os> <version>)`, and CI tags the
image with the commit SHA, so leaving the target in the fingerprint invalidated
the entire image baseline on every commit. A ZAP alert carries the URLs it was
seen at, and a concurrent crawl attaches the same alert to a different set of
URLs each run. Both are run-specific, and **anything run-specific must stay out
of the fingerprint** or the gate blocks on churn instead of on change.

### Secrets never reach the baseline in plaintext

Gitleaks runs twice: once producing a **redacted** SARIF that is safe to upload
and publish, and once producing an unredacted JSON that **never leaves the
runner**, is gitignored, and is never uploaded as an artifact. Only the
irreversible `sha256` of the secret reaches the committed baseline.

This is why hashing the secret, not the commit, is the right fingerprint: a
gitleaks-native fingerprint is commit-scoped, so the same leak reported from a
different commit during a PR diff scan would look brand new.

### The baseline is generated, never hand-written

```bash
make baseline-update      # re-runs the scanners, regenerates, prints a diff
```

Hand-written baseline entries are forbidden — an entry you have not observed in a
real scan is an assertion about a finding you have never seen. The generator
preserves justifications you have written by hand and assigns
`REVIEW REQUIRED - no justification recorded` to anything new. **A baseline
containing that string must not be merged.**

Cross-job integrity: scanning jobs normalize their own reports and pass only the
normalized findings onward. The gate **recomputes every fingerprint** from
`identity` rather than trusting the `key` field in the file, so a tampered
artifact cannot smuggle a finding past the gate by claiming a baselined key.

---

## 2. Severity thresholds

`.security/policy.json` is the machine-readable form of this section and is what
`.security/gate.py` actually reads. This prose is the contract with humans; that
file is the contract with CI. Keep them in sync.

**Default: `CRITICAL` and `HIGH` block. `MEDIUM` and below are reported.**

Per-scanner overrides, each with a reason:

| Scanner | Blocks on | Why |
| --- | --- | --- |
| **gitleaks** | any severity | A newly committed secret is never acceptable, whatever the rule's confidence. Rotate first, then rewrite history if it reached a shared branch. |
| **pip-audit** | any severity | pip-audit emits **no severity field at all**. Severity filtering would silently drop every finding, so any new advisory blocks and is triaged by hand. |
| **trivy-fs** | `CRITICAL`, `HIGH` | Dependency and licence findings at `MEDIUM` and below are recorded for visibility; the nightly run captures the full distribution. |
| **checkov** | any severity | Checkov community edition leaves `severity` **null** on every check — the same problem as pip-audit. It also only scans `deploy/`, which §3(b) treats as the security control rather than the vulnerable app, so a new finding there is a real finding. |
| **trivy-config** | any severity | Same reasoning as checkov: the target is the pipeline's own infrastructure code, so severity is the wrong filter for whether a new finding deserves attention. |
| **conftest** | any severity | A conftest failure means `deploy/k8s` violates `policy/kubernetes.rego` — a policy this repository wrote about its own infrastructure. There is nothing to weigh and nothing to accept. |

Severity normalization across tools:

- Bandit reports `HIGH`/`MEDIUM`/`LOW` directly.
- Semgrep carries severity only on the rule, as a SARIF level: `error` → `HIGH`,
  `warning` → `MEDIUM`, `note` → `LOW`. Where a rule exposes a numeric
  `security-severity`, that wins (≥9 `CRITICAL`, ≥7 `HIGH`, ≥4 `MEDIUM`).
- Trivy reports `CRITICAL`…`LOW` directly, for filesystem, image and config scans alike.
- Checkov reports no severity in the community edition, so every finding
  normalizes to `UNKNOWN` and the override above is what gives it teeth.
- Conftest reports no severity either. `failures` are recorded as `HIGH` and
  `warnings` as `MEDIUM`, since the policy author already decided which of the
  two a rule deserves by choosing the rule name.
- ZAP uses its own `riskcode`, which has no `CRITICAL`: 3 → `HIGH`, 2 →
  `MEDIUM`, 1 → `LOW`. `riskcode` 0 is *informational*, which is not a severity
  at all, so it becomes `UNKNOWN` rather than being flattened into `LOW`
  alongside genuine low-risk findings. ZAP takes the default threshold and gets
  no override: a new `HIGH` from a scanner that talks to a running application
  deserves to block on the same terms as anything else.
- Anything unmapped becomes `UNKNOWN`, which blocks only where a scanner
  override says so.

### The gate fails closed

If no scanner reports are found, the gate **fails** rather than passing
vacuously. A pipeline that silently reports success because a scanner crashed is
the single most dangerous failure mode in this design.

Scanners themselves are wired so that **findings never fail a step, but scanner
errors always do** — Bandit exit 1 (findings) passes, exit >1 (crash) fails. All
gating happens in one place, on normalized data, against this policy.

---

## 3. Requesting an exception

Two distinct cases. Do not conflate them.

### (a) Accepting a finding in the deliberately vulnerable application

Expected and routine — it is what the app is for.

1. Run `make baseline-update` and confirm the finding appears in the diff.
2. Replace the `REVIEW REQUIRED` text with a real justification. It must say
   **why this is intentional**, not merely that it is inconvenient. Name the lab
   or scenario where practical.
3. Commit `.security/baseline/` as part of the PR that surfaced the finding,
   never as a standalone "fix the build" commit.
4. In the PR description, state the finding count before and after.

A reviewer who cannot tell from the justification why a finding is acceptable
should reject the PR. "Pre-existing" is not a justification; it is a restatement
of the fingerprint.

### (b) Accepting a finding in the *pipeline itself*

Held to a different standard. The workflows, `Dockerfile`, `deploy/`, and
`policy/` directories are not part of the vulnerable app — they are the security
control. A finding there is a real finding.

Default answer is **fix it, do not baseline it**. When Semgrep flagged mutable
action tags in our own workflows, the fix was to pin every action to a commit
SHA, not to add six baseline entries.

To baseline one anyway, the PR must record:

- the finding and its fingerprint;
- why fixing it is not possible now;
- what compensating control exists;
- an expiry — a date or a linked issue. An exception with no end is a
  permanent hole with paperwork.

### (c) Emergency bypass

There is no bypass flag, and adding one is out of scope. If the gate must be
overridden, that is a branch-protection decision made by a human with admin
rights, recorded in the PR — see [`docs/BRANCH-PROTECTION.md`](../docs/BRANCH-PROTECTION.md).
The audit trail is the point.

---

## 4. Current baseline

Populated from real scan runs — see `generated_on` in each file. Counts at the
time of writing:

| Scanner | Accepted findings |
| --- | --- |
| bandit | 11 |
| semgrep | 31 |
| gitleaks | 10 |
| pip-audit | 80 |
| trivy-fs | 80 |
| trivy-image | 2675 |
| checkov | 0 |
| trivy-config | 1 |
| conftest | 0 |
| hadolint | 0 |
| zap | 16 |
| **Total entries** | **2904** |
| **Unique fingerprints** | **2904** |

Entries and unique fingerprints now agree. They did not always: `pip-audit`
reports one advisory once per matching dependency path, so 108 entries stood for
80 fingerprints. Loading always deduplicated, so the gate was never affected —
the file simply overstated what was accepted, and `write_baseline` no longer
writes a fingerprint twice.

Every entry traces to observed scanner output, with the scanner versions pinned
by digest in the workflows.

`trivy-image` is baselined from **CI** output, not from a developer machine. The
gate runs on amd64 runners, and an arm64 laptop cannot see the CVEs of
`libmpx2` and `libquadmath0` — x86-only GCC support libraries that ship only in
the amd64 image. A baseline generated locally reported those 4 as new HIGH
findings on every CI run. Local arm64 findings are a strict subset of amd64, so
an amd64-generated baseline is correct for both.

`conftest` contributing zero is the intended steady state, not a gap: a conftest
finding means the manifests violate our own policy, and §3(b) says fix it.

`checkov` contributing zero is the result of an exception being **closed rather
than renewed**. `CKV_K8S_43` ("image should use digest") was accepted under
§3(b) only while no image existed to pin: publishing is gated to pushes on
`main`, so before the first such push there was no digest in existence. The
first push produced one, `deploy/k8s/30-deployment.yaml` now pins it, and the
entry is deleted — which is what §3(b) means by an expiry.

The single `trivy-config` entry is the one remaining **exception with a recorded
expiry** — read its `justification` field. It closes if this Terraform is ever
pointed at a real AWS account.

Hadolint contributing zero is a real result, not a missing scanner: the
Dockerfile passes clean, verified against a deliberately bad Dockerfile to prove
the linter was actually evaluating.

`zap` is the only scanner whose finding set is not perfectly reproducible. The
crawl is concurrent and the passive-scan queue drains asynchronously, so
membership of the alert set can flap: across three runs of the committed
configuration, one informational alert (`10049-3`, "Storable and Cacheable
Content") appeared twice out of three, and instance counts moved. That flap is
left in place rather than suppressed — an intermittent alert is a real alert. A
run that does not reproduce a baselined alert reports it as a stale entry, which
is informational, and the one alert that flaps is `UNKNOWN`, which does not
block. Unlike `trivy-image`, ZAP baselines correctly from a laptop: its alerts
are properties of HTTP responses, not of the runner's architecture.

### Expect this baseline to drift, and expect that to be noisy

`trivy-image` accounts for 2675 of the 2904 entries, almost all of them unpatched
OS packages in the end-of-life Debian 10 base image. Because buster receives no
security updates, newly published CVEs against it will keep appearing, and each
one arrives as a **new** finding that blocks at `CRITICAL`/`HIGH`.

That is the intended signal, not a bug: an ever-growing baseline on an EOL base
image is the pipeline telling you the base image is rotting. The honest response
is to re-run `make baseline-update` and accept the drift *deliberately*, or to
move off buster. What the pipeline refuses to do is hide it.
