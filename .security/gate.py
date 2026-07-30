#!/usr/bin/env python3
"""Unified security finding normalizer, baseline manager, and policy gate.

PyGoat is deliberately vulnerable. A gate that fails on any critical finding
would leave this pipeline permanently red and therefore worthless. Instead:

  * every scanner report is normalized into a common finding shape
  * each finding gets a *location-independent* fingerprint, so shifting line
    numbers do not invalidate it
  * findings whose fingerprint appears in .security/baseline/ are accepted
  * the gate fails only on findings that are NOT baselined - regressions and
    newly introduced issues

Commands
--------
  collect   normalize all reports found in a directory, print/emit JSON
  baseline  regenerate .security/baseline/ from real scan output, print a diff
  gate      evaluate reports against the policy, emit a markdown summary

Exit codes: 0 = pass, 1 = policy violation, 2 = tool error.

Stdlib only, so it runs anywhere the pipeline runs with no install step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
SECURITY_DIR = REPO_ROOT / ".security"
POLICY_FILE = SECURITY_DIR / "policy.json"

SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Paths whose findings are, by design, intentionally vulnerable teaching code.
INTENTIONAL_PATH_RE = re.compile(
    r"^(pygoat/|chatbot/|Solutions/|introduction/|PyGoatBot\.py|temp\.py|setup\.py|manage\.py)"
)


# ---------------------------------------------------------------------------
# Normalized finding
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    scanner: str
    rule: str
    severity: str
    path: str
    title: str
    # Fingerprint inputs that are stable across line moves and reformatting.
    identity: str
    line: int | None = None
    meta: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        raw = "|".join([self.scanner, self.rule, self.path, self.identity])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]

    def to_baseline_entry(self, justification: str) -> dict:
        return {
            "key": self.key,
            "rule": self.rule,
            "severity": self.severity,
            "path": self.path,
            "title": self.title[:300],
            "justification": justification,
        }


def sev(value: str | None) -> str:
    if not value:
        return "UNKNOWN"
    v = str(value).strip().upper()
    return v if v in SEVERITY_ORDER else "UNKNOWN"


def norm_path(p: str | None) -> str:
    if not p:
        return "<unknown>"
    p = p.replace("\\", "/")
    for prefix in ("./", "/src/", "/repo/", "/github/workspace/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p.lstrip("/")


# Trivy names an image-scan result target after the artifact it scanned:
# "<image-ref> (<os> <version>)". The image ref is not a property of the
# finding - it carries the registry, repository and tag, and the tag is the
# commit SHA, so it changes on *every commit*. Left in the fingerprint it would
# invalidate the entire image baseline on each push and turn the gate into a
# permanent block. Strip it and key on the OS instead, which is what the CVE
# actually depends on. Same reasoning as excluding line numbers.
TRIVY_OS_TARGET = re.compile(r"^(?P<name>.+?) \((?P<os>[^()]+)\)$")


def norm_trivy_target(target: str | None, artifact: str | None) -> str:
    if not target:
        return "<unknown>"
    m = TRIVY_OS_TARGET.match(target.strip())
    if m and artifact and m.group("name") == artifact.strip():
        return f"({m.group('os')})"
    return norm_path(target)


def digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def squash(text: str | None) -> str:
    """Collapse whitespace so reindentation does not change a fingerprint."""
    return re.sub(r"\s+", " ", (text or "")).strip()


# ---------------------------------------------------------------------------
# Parsers - one per scanner report
# ---------------------------------------------------------------------------
def _load(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def parse_bandit(path: Path) -> list[Finding]:
    out = []
    for r in _load(path).get("results", []):
        out.append(
            Finding(
                scanner="bandit",
                rule=r.get("test_id", "?"),
                severity=sev(r.get("issue_severity")),
                path=norm_path(r.get("filename")),
                title=r.get("issue_text", ""),
                # The flagged source itself, not its line number.
                identity=digest(squash(r.get("code"))),
                line=r.get("line_number"),
                meta={"cwe": (r.get("issue_cwe") or {}).get("id"),
                      "confidence": r.get("issue_confidence")},
            )
        )
    return out


_SARIF_LEVEL_TO_SEV = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}


def _sarif_rule_index(run: dict) -> dict:
    driver = (run.get("tool") or {}).get("driver") or {}
    return {r.get("id"): r for r in (driver.get("rules") or []) if r.get("id")}


def _sarif_severity(result: dict, rule: dict) -> str:
    # Semgrep puts severity only on the rule; other tools set it per result.
    ssev = (rule.get("properties") or {}).get("security-severity")
    if ssev is not None:
        try:
            score = float(ssev)
        except (TypeError, ValueError):
            score = -1.0
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score >= 0.0:
            return "LOW"
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return _SARIF_LEVEL_TO_SEV.get(str(level).lower(), "UNKNOWN")


def _sarif_location(result: dict) -> tuple[str, int | None, str]:
    locs = result.get("locations") or []
    if not locs:
        return "<unknown>", None, ""
    phys = (locs[0] or {}).get("physicalLocation") or {}
    uri = ((phys.get("artifactLocation") or {}).get("uri")) or "<unknown>"
    region = phys.get("region") or {}
    snippet = ((region.get("snippet") or {}).get("text")) or ""
    return norm_path(uri), region.get("startLine"), snippet


def parse_sarif(scanner: str) -> Callable[[Path], list[Finding]]:
    def _parse(path: Path) -> list[Finding]:
        out: list[Finding] = []
        for run in _load(path).get("runs", []):
            rules = _sarif_rule_index(run)
            for res in run.get("results") or []:
                rule_id = res.get("ruleId") or "?"
                rule = rules.get(rule_id, {})
                p, line, snippet = _sarif_location(res)
                msg = ((res.get("message") or {}).get("text")) or rule_id
                # Prefer the matched source text; fall back to the message when a
                # tool omits snippets (line numbers are deliberately excluded).
                out.append(
                    Finding(
                        scanner=scanner,
                        rule=rule_id,
                        severity=_sarif_severity(res, rule),
                        path=p,
                        title=msg,
                        identity=digest(squash(snippet) or squash(msg)),
                        line=line,
                    )
                )
        return out

    return _parse


def parse_gitleaks_json(path: Path) -> list[Finding]:
    """Unredacted gitleaks JSON: fingerprint on a hash of the secret itself.

    The plaintext report never leaves the runner and is gitignored; only the
    irreversible hash reaches the committed baseline. Hashing the secret makes
    the fingerprint survive the commit rewrites and line moves that make
    gitleaks' own commit-scoped fingerprint useless for a PR diff scan.
    """
    out = []
    for f in _load(path):
        secret = f.get("Secret") or f.get("Match") or ""
        out.append(
            Finding(
                scanner="gitleaks",
                rule=f.get("RuleID", "?"),
                # Policy treats any new secret as critical regardless of rule.
                severity="CRITICAL",
                path=norm_path(f.get("File")),
                title=f.get("Description", "secret detected"),
                identity=digest(hashlib.sha256(secret.encode("utf-8")).hexdigest()),
                line=f.get("StartLine"),
                meta={"entropy": f.get("Entropy"), "commit": f.get("Commit")},
            )
        )
    return out


def parse_pip_audit(path: Path) -> list[Finding]:
    out = []
    for dep in _load(path).get("dependencies", []):
        name = dep.get("name", "?")
        version = dep.get("version", "?")
        for v in dep.get("vulns") or []:
            out.append(
                Finding(
                    scanner="pip-audit",
                    rule=v.get("id", "?"),
                    # pip-audit reports no severity at all - see POLICY.md, which
                    # is why its threshold is "any new finding blocks".
                    severity="UNKNOWN",
                    path=f"{name}@{version}",
                    title=squash(v.get("description"))[:200],
                    # Version is part of identity on purpose: bumping a package
                    # must not silently inherit the old package's acceptance.
                    identity=digest(name, version, v.get("id", "?")),
                    meta={"fix_versions": v.get("fix_versions"), "aliases": v.get("aliases")},
                )
            )
    return out


def parse_trivy_json(scanner: str) -> Callable[[Path], list[Finding]]:
    def _parse(path: Path) -> list[Finding]:
        out: list[Finding] = []
        doc = _load(path)
        artifact = doc.get("ArtifactName")
        for res in doc.get("Results") or []:
            target = norm_trivy_target(res.get("Target"), artifact)
            for v in res.get("Vulnerabilities") or []:
                pkg = v.get("PkgName", "?")
                ver = v.get("InstalledVersion", "?")
                out.append(
                    Finding(
                        scanner=scanner,
                        rule=v.get("VulnerabilityID", "?"),
                        severity=sev(v.get("Severity")),
                        path=f"{target}:{pkg}@{ver}",
                        title=squash(v.get("Title") or v.get("Description"))[:200],
                        identity=digest(pkg, ver, v.get("VulnerabilityID", "?")),
                        meta={"fixed_version": v.get("FixedVersion")},
                    )
                )
            for s in res.get("Secrets") or []:
                out.append(
                    Finding(
                        scanner=scanner,
                        rule=s.get("RuleID", "?"),
                        severity=sev(s.get("Severity")),
                        path=target,
                        title=squash(s.get("Title"))[:200],
                        identity=digest(hashlib.sha256(
                            (s.get("Match") or "").encode("utf-8")).hexdigest()),
                        line=s.get("StartLine"),
                    )
                )
            for m in res.get("Misconfigurations") or []:
                out.append(
                    Finding(
                        scanner=scanner,
                        rule=m.get("ID", "?"),
                        severity=sev(m.get("Severity")),
                        path=target,
                        title=squash(m.get("Title"))[:200],
                        identity=digest(m.get("ID", "?"), squash(m.get("Message"))),
                        line=((m.get("CauseMetadata") or {}).get("StartLine")),
                    )
                )
            for lic in res.get("Licenses") or []:
                out.append(
                    Finding(
                        scanner=scanner,
                        rule=f"license/{lic.get('Name', '?')}",
                        severity=sev(lic.get("Severity")),
                        path=norm_path(lic.get("FilePath")) if lic.get("FilePath") else target,
                        title=f"{lic.get('PkgName', '?')} uses {lic.get('Name', '?')}",
                        identity=digest(lic.get("PkgName", "?"), lic.get("Name", "?")),
                    )
                )
        return out

    return _parse


def parse_normalized(path: Path) -> list[Finding]:
    """Re-read this tool's own `collect` output.

    Scanning jobs normalize their reports in place and pass only the result
    between jobs. That keeps raw scanner output - which for gitleaks contains
    plaintext secrets - off the artifact store, while the gate job still sees
    every finding. Fingerprints are recomputed from identity, never trusted
    from the file, so a tampered artifact cannot smuggle a finding past the
    gate by claiming a baselined key.
    """
    data = _load(path)
    out = []
    for f in data.get("findings", []):
        out.append(
            Finding(
                scanner=f.get("scanner", "unknown"),
                rule=f.get("rule", "?"),
                severity=sev(f.get("severity")),
                path=f.get("path", "<unknown>"),
                title=f.get("title", ""),
                identity=f.get("identity", ""),
                line=f.get("line"),
                meta=f.get("meta") or {},
            )
        )
    return out


def parse_checkov(path: Path) -> list[Finding]:
    """Checkov JSON.

    With more than one --framework, checkov emits a *list* of per-framework result
    objects rather than a single object, so both shapes are handled: a future
    single-framework invocation must not silently parse to zero findings.

    Checkov community edition leaves `severity` null on every check, so severity
    filtering would drop the lot. .security/policy.json therefore gives checkov the
    same override as pip-audit - any new finding blocks - rather than pretending a
    severity exists.
    """
    doc = _load(path)
    frameworks = doc if isinstance(doc, list) else [doc]
    out: list[Finding] = []
    for fw in frameworks:
        for c in (fw.get("results") or {}).get("failed_checks") or []:
            rng = c.get("file_line_range") or []
            out.append(
                Finding(
                    scanner="checkov",
                    rule=c.get("check_id", "?"),
                    severity=sev(c.get("severity")),
                    path=norm_path(c.get("file_path")),
                    title=squash(c.get("check_name"))[:200],
                    # The resource address rather than the line range: moving a
                    # resource within a file must not look like a new finding.
                    identity=digest(c.get("resource") or "?", c.get("check_id", "?")),
                    line=rng[0] if rng else None,
                    meta={"guideline": c.get("guideline")},
                )
            )
    return out


def parse_conftest(path: Path) -> list[Finding]:
    """Conftest JSON.

    Conftest reports no severity, so `failures` are treated as HIGH and `warnings`
    as MEDIUM. This is the one scanner whose baseline should stay empty: a conftest
    failure means deploy/k8s violates policy/kubernetes.rego, which the pipeline
    itself owns and must fix rather than accept.

    Identity is the message text, since these rules carry no stable per-rule ID.
    Rewording a message therefore invalidates its fingerprint - acceptable here
    precisely because nothing should be baselined for this scanner anyway.
    """
    out: list[Finding] = []
    for result in _load(path) or []:
        target = norm_path(result.get("filename"))
        namespace = result.get("namespace") or "main"
        for level, severity in (("failures", "HIGH"), ("warnings", "MEDIUM")):
            for f in result.get(level) or []:
                msg = squash(f.get("msg"))
                out.append(
                    Finding(
                        scanner="conftest",
                        rule=(f.get("metadata") or {}).get("id") or f"policy/{namespace}",
                        severity=severity,
                        path=target,
                        title=msg[:200],
                        identity=digest(hashlib.sha256(msg.encode("utf-8")).hexdigest()),
                    )
                )
    return out


# ZAP reports one alert per site, with an `instances` list of the URLs where it
# was observed. Those URLs must not reach the fingerprint, for two reasons.
#
# The host and port belong to the ephemeral Compose deployment, not to the
# application - the same category of mistake as the image tag in
# norm_trivy_target, arriving by a third route.
#
# More importantly, the URL set is not stable. The crawl is concurrent and the
# passive-scan queue drains asynchronously, so the same application scanned
# twice attaches its alerts to overlapping but different URLs. Measured over
# three runs of the committed configuration: instance counts moved (10112 went
# from 10 to 12) and one informational alert appeared in two runs out of three
# (10049-3, "Storable and Cacheable Content"). Everything else was identical.
#
# So the fingerprint is the alert identity alone: plugin ID plus alertRef, which
# distinguishes the variants a single plugin can raise (90004-1 vs 90004-2). The
# URLs are still recorded, in meta, where someone triaging the finding can read
# them and no fingerprint depends on them.
#
# That leaves alert *membership* as the one thing that can still flap, and it is
# left flapping on purpose. An intermittent alert is a real alert; suppressing
# it would be the wrong fix. Once baselined it is accepted, and a run that does
# not reproduce it is reported as a stale baseline entry, which is informational
# and does not fail anything.
ZAP_SITE_LABEL = "dast:pygoat"

# riskcode is ZAP's own scale. It has no CRITICAL: 3 is its top severity, which
# maps to HIGH so it blocks under the default policy. riskcode 0 is
# informational, which is not a severity at all, so it becomes UNKNOWN rather
# than being flattened into LOW alongside genuine low-risk findings.
_ZAP_RISK_TO_SEV = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "UNKNOWN"}

# How many example URLs to keep per alert. Enough to triage, few enough that the
# baseline stays readable - and they are outside the fingerprint, so a change in
# the examples costs nothing.
ZAP_MAX_EXAMPLES = 5


def _zap_uri_path(uri: str | None) -> str:
    """Path component of a URL, without scheme, host, port or query string."""
    if not uri:
        return "/"
    without_scheme = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*", "", uri.strip())
    path = without_scheme.split("?", 1)[0].split("#", 1)[0]
    return path or "/"


def parse_zap(path: Path) -> list[Finding]:
    """OWASP ZAP baseline report (`zap-baseline.py -J`).

    One Finding per alert per site. See ZAP_SITE_LABEL above for why neither the
    site's host and port nor the instance URLs take part in the fingerprint.
    """
    out: list[Finding] = []
    for site in _load(path).get("site") or []:
        for alert in site.get("alerts") or []:
            plugin = str(alert.get("pluginid") or "?")
            ref = str(alert.get("alertRef") or plugin)
            instances = alert.get("instances") or []
            paths = sorted({_zap_uri_path(i.get("uri")) for i in instances})
            out.append(
                Finding(
                    scanner="zap",
                    rule=ref,
                    severity=sev(_ZAP_RISK_TO_SEV.get(str(alert.get("riskcode")))),
                    path=ZAP_SITE_LABEL,
                    title=squash(alert.get("name") or alert.get("alert"))[:200],
                    identity=digest(plugin, ref),
                    meta={
                        "cwe": alert.get("cweid"),
                        "wasc": alert.get("wascid"),
                        "confidence": alert.get("confidence"),
                        "instances": int(alert.get("count") or len(instances)),
                        "example_paths": paths[:ZAP_MAX_EXAMPLES],
                    },
                )
            )
    return out


# Report filename -> (scanner name, parser). Later phases extend this table.
# Gitleaks intentionally prefers the unredacted local JSON; the redacted SARIF is
# the fallback so the gate still works when only artifacts are available.
REPORT_PARSERS: list[tuple[str, str, Callable[[Path], list[Finding]]]] = [
    ("bandit.json", "bandit", parse_bandit),
    ("semgrep.sarif", "semgrep", parse_sarif("semgrep")),
    (".gitleaks-unredacted.json", "gitleaks", parse_gitleaks_json),
    ("gitleaks.sarif", "gitleaks", parse_sarif("gitleaks")),
    ("pip-audit.json", "pip-audit", parse_pip_audit),
    ("trivy-fs.json", "trivy-fs", parse_trivy_json("trivy-fs")),
    ("hadolint.sarif", "hadolint", parse_sarif("hadolint")),
    ("trivy-image.json", "trivy-image", parse_trivy_json("trivy-image")),
    ("scout-report.sarif", "scout", parse_sarif("scout")),
    # Stage 4 - provision. trivy config reuses the Trivy parser: its findings
    # arrive in the same Results[].Misconfigurations shape as any other Trivy scan.
    ("checkov.json", "checkov", parse_checkov),
    ("trivy-config.json", "trivy-config", parse_trivy_json("trivy-config")),
    ("conftest.json", "conftest", parse_conftest),
    # Stage 5 - deploy and DAST.
    ("zap.json", "zap", parse_zap),
]


def collect(reports_dir: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    seen_scanners: set[str] = set()
    sources: list[str] = []

    # Pre-normalized stage output wins over raw reports for the same scanner.
    for path in sorted(reports_dir.rglob("normalized-*.json")):
        found = parse_normalized(path)
        for f in found:
            seen_scanners.add(f.scanner)
        sources.append(f"{path.name} -> {len(found)} normalized findings")
        findings.extend(found)

    for filename, scanner, parser in REPORT_PARSERS:
        if scanner in seen_scanners:
            continue  # a higher-priority report for this scanner already parsed
        path = reports_dir / filename
        if not path.is_file():
            continue
        try:
            found = parser(path)
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            print(f"::error title=gate::cannot parse {path}: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        seen_scanners.add(scanner)
        sources.append(f"{filename} -> {scanner}: {len(found)} findings")
        findings.extend(found)
    return findings, sources


# ---------------------------------------------------------------------------
# Policy and baseline
# ---------------------------------------------------------------------------
DEFAULT_POLICY = {
    "fail_on_severities": ["CRITICAL", "HIGH"],
    "scanner_overrides": {},
    "baseline_dir": ".security/baseline",
}


def load_policy() -> dict:
    if POLICY_FILE.is_file():
        policy = dict(DEFAULT_POLICY)
        policy.update(_load(POLICY_FILE))
        return policy
    return dict(DEFAULT_POLICY)


def blocking_severities(policy: dict, scanner: str) -> set[str]:
    override = (policy.get("scanner_overrides") or {}).get(scanner) or {}
    return set(override.get("fail_on_severities") or policy["fail_on_severities"])


def baseline_dir(policy: dict) -> Path:
    return REPO_ROOT / policy.get("baseline_dir", ".security/baseline")


def load_baseline(policy: dict) -> dict[str, dict]:
    """Return {key: entry} across every baseline file."""
    entries: dict[str, dict] = {}
    bdir = baseline_dir(policy)
    if not bdir.is_dir():
        return entries
    for f in sorted(bdir.glob("*.json")):
        data = _load(f)
        for entry in data.get("findings", []):
            if entry.get("key"):
                entries[entry["key"]] = {**entry, "_file": f.name}
    return entries


def default_justification(f: Finding) -> str:
    if f.scanner == "gitleaks":
        return (
            "Fake credential committed as part of a PyGoat lab exercise. Not a live "
            "secret; kept so the secret-scanning lesson still demonstrates a hit."
        )
    if f.scanner in ("pip-audit", "trivy-fs") and ("@" in f.path or "requirements" in f.path):
        return (
            "Vulnerable dependency pin inherited from upstream PyGoat. Upgrading breaks "
            "the lab scenarios that depend on the old behaviour. Tracked by Dependabot; "
            "accepted for the demo application only."
        )
    if f.scanner in ("trivy-image", "scout"):
        return (
            "Unpatched OS or runtime package in the end-of-life Debian 10 base image "
            "(python:3.11.0b1-buster). The EOL base is retained deliberately: its CVE "
            "surface is what the image-scanning stage exists to demonstrate, and no "
            "security updates are published for buster to apply. Not deployed to any "
            "environment that matters."
        )
    # Stage 4 scanners cover deploy/ and policy/, which POLICY.md 3(b) treats as
    # the security control rather than the vulnerable application. There is
    # deliberately no generated justification for them: a finding here is a real
    # finding, and the default answer is to fix it. Anything genuinely accepted
    # needs a hand-written exception with an expiry, so REVIEW REQUIRED is the
    # correct output and `make baseline-update` will keep printing it until a
    # human writes one.
    if f.scanner in ("checkov", "trivy-config", "conftest"):
        return (
            f"REVIEW REQUIRED - {f.scanner} finding in the pipeline's own "
            "infrastructure code. POLICY.md 3(b): fix it, or record an exception "
            "with a compensating control and an expiry. Do not merge with this "
            "text in place."
        )
    if f.scanner == "zap":
        return (
            "Runtime finding against the deliberately vulnerable PyGoat application, "
            "observed by the DAST stage over HTTP. The application's responses are the "
            "teaching material and this repository does not modify app code. Anything "
            "here that is genuinely a property of the *deployment* rather than of "
            "PyGoat - a missing response header the settings overlay could set, for "
            "instance - is a POLICY.md 3(b) finding in the pipeline's own "
            "configuration and should be fixed in deploy/overlay/ instead of accepted "
            "here."
        )
    if INTENTIONAL_PATH_RE.match(f.path):
        return (
            f"Intentional vulnerability in PyGoat lab code ({f.rule}). The application is a "
            "deliberately insecure teaching target; this finding is the lesson, not a defect."
        )
    return "REVIEW REQUIRED - no justification recorded. Do not merge with this text in place."


def write_baseline(policy: dict, findings: list[Finding]) -> tuple[dict, dict]:
    """Regenerate baseline files, preserving hand-written justifications.

    Returns (added, removed) keyed by fingerprint for the review diff.
    """
    existing = load_baseline(policy)
    bdir = baseline_dir(policy)
    bdir.mkdir(parents=True, exist_ok=True)

    by_scanner: dict[str, list[Finding]] = {}
    for f in findings:
        by_scanner.setdefault(f.scanner, []).append(f)

    current_keys = {f.key for f in findings}
    added = {f.key: f for f in findings if f.key not in existing}
    scanners_now = set(by_scanner)
    removed = {
        k: v for k, v in existing.items()
        if k not in current_keys and v.get("_file", "").removesuffix(".json") in scanners_now
    }

    for scanner, items in sorted(by_scanner.items()):
        entries = []
        seen: set[str] = set()
        for f in sorted(items, key=lambda x: (x.path, x.rule, x.key)):
            if f.key in seen:  # a scanner can report one advisory twice (pip-audit does)
                continue
            seen.add(f.key)
            prior = existing.get(f.key)
            justification = (
                prior.get("justification") if prior and prior.get("justification")
                else default_justification(f)
            )
            entries.append(f.to_baseline_entry(justification))
        payload = {
            "scanner": scanner,
            "generated_on": date.today().isoformat(),
            "generated_by": "make baseline-update (.security/gate.py baseline)",
            "note": (
                "Accepted findings for a deliberately vulnerable application. Keys are "
                "location-independent fingerprints; the gate fails on any finding whose "
                "key is absent here. Never add an entry you have not observed in a real "
                "scan - regenerate instead of hand-editing keys."
            ),
            "count": len(entries),
            "findings": entries,
        }
        (bdir / f"{scanner}.json").write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )
    return added, removed


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------
def severity_rank(s: str) -> int:
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 0


def evaluate(policy: dict, findings: list[Finding]) -> dict:
    baseline = load_baseline(policy)
    per_scanner: dict[str, dict] = {}
    blocking: list[Finding] = []
    new_non_blocking: list[Finding] = []

    for f in findings:
        st = per_scanner.setdefault(
            f.scanner,
            {"total": 0, "baselined": 0, "new": 0, "new_blocking": 0,
             "thresholds": sorted(blocking_severities(policy, f.scanner), key=severity_rank,
                                  reverse=True)},
        )
        st["total"] += 1
        if f.key in baseline:
            st["baselined"] += 1
            continue
        st["new"] += 1
        if f.severity in blocking_severities(policy, f.scanner):
            st["new_blocking"] += 1
            blocking.append(f)
        else:
            new_non_blocking.append(f)

    current_keys = {f.key for f in findings}
    scanners_present = {f.scanner for f in findings}
    stale = [
        {"key": k, **{x: v[x] for x in ("rule", "path", "severity") if x in v}}
        for k, v in baseline.items()
        if k not in current_keys and v.get("_file", "").removesuffix(".json") in scanners_present
    ]

    return {
        "per_scanner": per_scanner,
        "blocking": blocking,
        "new_non_blocking": new_non_blocking,
        "stale_baseline": stale,
        "baseline_size": len(baseline),
        "passed": not blocking,
    }


def render_summary(result: dict, sources: list[str]) -> str:
    lines = ["## Security gate", ""]
    verdict = "✅ **PASS**" if result["passed"] else "❌ **FAIL**"
    lines.append(f"{verdict} — {len(result['blocking'])} non-baselined blocking finding(s), "
                 f"baseline holds {result['baseline_size']} accepted finding(s).")
    lines += ["", "| Scanner | Total | Baselined | New | New blocking | Blocks on |",
              "| --- | --: | --: | --: | --: | --- |"]
    for scanner, st in sorted(result["per_scanner"].items()):
        lines.append(
            f"| {scanner} | {st['total']} | {st['baselined']} | {st['new']} | "
            f"{st['new_blocking']} | {', '.join(st['thresholds'])} |"
        )

    if result["blocking"]:
        lines += ["", "### Blocking findings (not in baseline)", ""]
        for f in sorted(result["blocking"],
                        key=lambda x: (-severity_rank(x.severity), x.scanner, x.path))[:50]:
            loc = f"{f.path}:{f.line}" if f.line else f.path
            lines.append(f"- **{f.severity}** `{f.scanner}` `{f.rule}` — {loc}<br>{f.title[:200]}")
        if len(result["blocking"]) > 50:
            lines.append(f"- …and {len(result['blocking']) - 50} more")
        lines += ["", "Fix the finding, or request an exception per "
                      "[`.security/POLICY.md`](../.security/POLICY.md)."]

    if result["new_non_blocking"]:
        lines += ["", f"<details><summary>{len(result['new_non_blocking'])} new finding(s) "
                      "below the blocking threshold</summary>", ""]
        for f in result["new_non_blocking"][:50]:
            lines.append(f"- {f.severity} `{f.scanner}` `{f.rule}` — {f.path}")
        lines += ["", "</details>"]

    if result["stale_baseline"]:
        lines += ["", f"<details><summary>{len(result['stale_baseline'])} stale baseline "
                      "entry/entries no longer observed — run `make baseline-update`"
                      "</summary>", ""]
        for e in result["stale_baseline"][:50]:
            lines.append(f"- `{e.get('rule')}` — {e.get('path')}")
        lines += ["", "</details>"]

    if sources:
        lines += ["", "<details><summary>Reports consumed</summary>", ""]
        lines += [f"- {s}" for s in sources]
        lines += ["", "</details>"]
    return "\n".join(lines) + "\n"


def emit(text: str, summary_path: str | None) -> None:
    print(text)
    target = summary_path or os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(text)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def cmd_collect(args: argparse.Namespace) -> int:
    findings, sources = collect(Path(args.reports))
    payload = [
        {"key": f.key, "scanner": f.scanner, "rule": f.rule, "severity": f.severity,
         "path": f.path, "line": f.line, "title": f.title, "identity": f.identity,
         "meta": f.meta}
        for f in findings
    ]
    text = json.dumps({"sources": sources, "findings": payload}, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {len(payload)} normalized findings to {args.out}")
        for s in sources:
            print(f"  {s}")
    else:
        print(text)
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    policy = load_policy()
    findings, sources = collect(Path(args.reports))
    if not findings:
        print("no findings parsed - refusing to write an empty baseline "
              "(did the scanners run? check the reports directory)", file=sys.stderr)
        return 2
    added, removed = write_baseline(policy, findings)

    print("Baseline regenerated from real scan output:")
    for s in sources:
        print(f"  {s}")
    print(f"\n  +{len(added)} newly accepted, -{len(removed)} no longer observed\n")
    for key, f in sorted(added.items(), key=lambda kv: (kv[1].scanner, kv[1].path)):
        print(f"  + [{f.severity:8}] {f.scanner:10} {f.rule:22} {f.path} ({key})")
    for key, e in sorted(removed.items(), key=lambda kv: kv[1].get("path", "")):
        print(f"  - [{e.get('severity', '?'):8}] {e.get('_file', '?'):15} "
              f"{e.get('rule', '?'):22} {e.get('path')} ({key})")
    unjustified = [
        e for e in load_baseline(policy).values()
        if e.get("justification", "").startswith("REVIEW REQUIRED")
    ]
    if unjustified:
        print(f"\n  {len(unjustified)} entry/entries need a written justification "
              "before commit:")
        for e in unjustified[:20]:
            print(f"      {e.get('rule')} {e.get('path')}")
    print("\nReview the diff above, then commit .security/baseline/.")
    return 0


def cmd_gate(args: argparse.Namespace) -> int:
    policy = load_policy()
    findings, sources = collect(Path(args.reports))
    if not findings and not args.allow_empty:
        print("::error title=Security gate::no scanner reports found in "
              f"{args.reports} - failing rather than passing vacuously", file=sys.stderr)
        return 2
    result = evaluate(policy, findings)
    emit(render_summary(result, sources), args.summary)
    if not result["passed"]:
        for f in result["blocking"][:20]:
            loc = f"file={f.path}" + (f",line={f.line}" if f.line else "")
            print(f"::error title=New {f.severity} {f.scanner} finding,{loc}::"
                  f"{f.rule} {f.title[:150]}")
        return 1
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="normalize reports to a single JSON document")
    c.add_argument("--reports", default="reports")
    c.add_argument("--out")
    c.set_defaults(func=cmd_collect)

    b = sub.add_parser("baseline", help="regenerate .security/baseline/ and print a diff")
    b.add_argument("--reports", default="reports")
    b.set_defaults(func=cmd_baseline)

    g = sub.add_parser("gate", help="evaluate reports against .security/policy.json")
    g.add_argument("--reports", default="reports")
    g.add_argument("--summary", help="markdown summary destination "
                                     "(defaults to $GITHUB_STEP_SUMMARY)")
    g.add_argument("--allow-empty", action="store_true",
                   help="do not fail when no reports are present")
    g.set_defaults(func=cmd_gate)

    args = ap.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
