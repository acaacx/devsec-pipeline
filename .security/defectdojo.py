#!/usr/bin/env python3
"""Publish the normalized findings to DefectDojo.

The pipeline already has one place that knows every finding and its acceptance
state - .security/gate.py. This reuses that instead of handing DefectDojo eleven
raw scanner reports:

  * one code path, not eleven native parser names to keep matching a moving
    upstream. DefectDojo renames and deprecates parsers between releases, and a
    silently unrecognised `scan_type` imports zero findings while returning 201.
  * the fingerprint the gate reasons about becomes DefectDojo's
    `unique_id_from_tool`, so where deduplication is switched on it keys on the
    same identity the gate uses - and therefore survives the line-number and
    image-tag churn gate.py's fingerprints were designed to absorb, rather than
    reporting a wave of "new" findings the gate considers unchanged.
  * the baseline maps onto DefectDojo's own risk-acceptance state, so the
    dashboard distinguishes "accepted, with a written justification" from "new
    and unreviewed" - which is the distinction this repository is about.

The cost is that DefectDojo's per-scanner CVSS enrichment is skipped for
findings whose rule is not a recognisable vulnerability ID. Rules that are
(CVE-*, GHSA-*, PYSEC-*, OSV-*) are passed as `vulnerability_ids`, so DefectDojo
still links those to its own vulnerability data.

Commands
--------
  render  write a Generic Findings Import document from the reports
  push    render, then POST it to DefectDojo's import-scan API
  token   exchange a username and password for an API token, and print it

Exit codes: 0 = ok, 2 = tool error.

Stdlib only, like gate.py - no install step, and the multipart body is built by
hand rather than pulling in requests.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate import (  # noqa: E402  - deliberate: gate.py is the shared normalizer
    Finding,
    collect,
    load_baseline,
    load_policy,
    blocking_severities,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

# DefectDojo's Finding.severity has exactly five values. Our UNKNOWN means "the
# scanner reported no severity at all" (pip-audit) rather than "harmless", so it
# lands on Info and carries a tag saying so - understating it silently would be
# worse than the mapping being visibly lossy. The gate, not DefectDojo, is what
# blocks on those.
SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Info",
}

VULN_ID_PREFIXES = ("CVE-", "GHSA-", "PYSEC-", "OSV-", "GMS-", "DSA-", "DLA-")

# ZAP is the only scanner here that talks to a running application. DefectDojo
# splits its metrics by this, and it is the same static/dynamic line the
# pipeline's stage numbering draws.
DYNAMIC_SCANNERS = {"zap"}


def _fix_hint(f: Finding) -> str:
    """Turn whatever fix information the scanner gave us into a mitigation."""
    fixed = f.meta.get("fixed_version")
    versions = f.meta.get("fix_versions")
    if isinstance(versions, list) and versions:
        fixed = ", ".join(str(v) for v in versions)
    if fixed:
        return f"Upgrade the affected package to {fixed}."
    return ""


def _describe(f: Finding, entry: dict | None, blocks_on: set[str]) -> str:
    """The finding body, including why it is or is not accepted.

    The justification text lives here rather than in `mitigation`: it explains
    why the finding is tolerated, which is the opposite of how to fix it.
    """
    lines = [
        f.title or "(no description reported by the scanner)",
        "",
        f"- Scanner: `{f.scanner}`",
        f"- Rule: `{f.rule}`",
        f"- Location: `{f.path}`" + (f" line {f.line}" if f.line else ""),
        f"- Normalized severity: `{f.severity}`"
        + (" (scanner reported none)" if f.severity == "UNKNOWN" else ""),
        f"- Gate fingerprint: `{f.key}`",
        f"- Blocks the build at: {', '.join(sorted(blocks_on)) or 'nothing'}",
    ]
    for k, v in sorted(f.meta.items()):
        # cwe is promoted to DefectDojo's own field, so it is not repeated here.
        if k != "cwe" and v not in (None, "", [], {}):
            lines.append(f"- {k}: `{v}`")
    if entry:
        lines += [
            "",
            "**Accepted by `.security/baseline/"
            f"{entry.get('_file', '?')}`** — see `.security/POLICY.md`.",
            "",
            "> " + (entry.get("justification") or "(no justification recorded)"),
        ]
        if entry.get("expires"):
            lines.append(f"\nException expires: **{entry['expires']}**.")
    else:
        lines += [
            "",
            "**Not in the baseline.** Either it is new since the baseline was "
            "taken, or it is a regression. Fix it, or record an exception with a "
            "compensating control and an expiry per `.security/POLICY.md` §3(b).",
        ]
    return "\n".join(lines)


def build_payload(findings: list[Finding], policy: dict, baseline: dict) -> dict:
    items = []
    for f in findings:
        entry = baseline.get(f.key)
        blocks_on = blocking_severities(policy, f.scanner)
        tags = [
            f"scanner:{f.scanner}",
            "baselined" if entry else "new",
        ]
        if f.severity == "UNKNOWN":
            tags.append("severity:unreported")
        if not entry and f.severity in blocks_on:
            tags.append("blocking")
        if entry and entry.get("expires"):
            tags.append(f"expires:{entry['expires']}")

        item = {
            # Required trio: title, severity, description.
            "title": f"{f.rule}: {f.path}"[:500],
            "severity": SEVERITY_MAP.get(f.severity, "Info"),
            "description": _describe(f, entry, blocks_on),
            # The gate's fingerprint is the identity DefectDojo dedupes on, so
            # the two systems cannot disagree about what a "new" finding is.
            "unique_id_from_tool": f.key,
            "vuln_id_from_tool": f.rule[:500],
            "file_path": f.path[:4000],
            "service": f.scanner,
            "tags": tags,
            "static_finding": f.scanner not in DYNAMIC_SCANNERS,
            "dynamic_finding": f.scanner in DYNAMIC_SCANNERS,
            # A baselined finding is an accepted risk with a written
            # justification, which is exactly DefectDojo's risk_accepted state.
            # `active` is deliberately not set per finding: the import-scan
            # request carries its own active/verified flags and they win, so a
            # per-finding value here would look meaningful and do nothing.
            # Active-and-risk-accepted is also the honest reading - the finding
            # is still present, and it is still accepted.
            "verified": False,
            "risk_accepted": bool(entry),
        }
        if f.line:
            item["line"] = f.line
        # ZAP is the only parser that carries a CWE through; DefectDojo groups
        # and reports on this field, so it is worth promoting where we have it.
        cwe = f.meta.get("cwe")
        if isinstance(cwe, int) or (isinstance(cwe, str) and cwe.isdigit()):
            item["cwe"] = int(cwe)
        if f.rule.upper().startswith(VULN_ID_PREFIXES):
            item["vulnerability_ids"] = [f.rule]
        hint = _fix_hint(f)
        if hint:
            item["mitigation"] = hint
        items.append(item)

    return {
        # Top-level keys the generic JSON parser understands.
        "name": "PyGoat security pipeline",
        "type": "Generic Findings Import",
        "description": (
            "Normalized output of every scanner in .github/workflows/ci.yml, "
            "produced by .security/gate.py. Findings tagged `baselined` are "
            "accepted in .security/baseline/ with a written justification; "
            "findings tagged `new` are not."
        ),
        "findings": items,
    }


# ---------------------------------------------------------------------------
# HTTP - multipart/form-data by hand, stdlib only
# ---------------------------------------------------------------------------
def _multipart(fields: dict[str, str], filename: str, content: bytes) -> tuple[str, bytes]:
    boundary = f"----defectdojo{uuid.uuid4().hex}"
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    out = bytearray()
    for key, value in fields.items():
        out += (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
            f"{value}\r\n"
        ).encode("utf-8")
    out += (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {ctype}\r\n\r\n"
    ).encode("utf-8")
    out += content + b"\r\n"
    out += f"--{boundary}--\r\n".encode("utf-8")
    return f"multipart/form-data; boundary={boundary}", bytes(out)


def _opener() -> urllib.request.OpenerDirector:
    """An opener that speaks HTTP and HTTPS, and nothing else.

    urllib's default opener also handles `file:`, `ftp:` and `data:` URLs, so a
    DEFECTDOJO_URL of `file:///etc/passwd` would be opened without complaint -
    which is exactly what bandit's B310 warns about. Building the opener from an
    empty OpenerDirector removes the capability rather than guarding it: the
    handlers for those schemes are never installed.
    """
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler,          # keep proxy env vars working
        urllib.request.HTTPHandler,
        urllib.request.HTTPSHandler,
        urllib.request.HTTPDefaultErrorHandler,   # 4xx/5xx raise HTTPError
        urllib.request.HTTPRedirectHandler,
        urllib.request.HTTPErrorProcessor,
    ):
        opener.add_handler(handler())
    return opener


def _open(req: urllib.request.Request) -> dict:
    # Checked as well as removed, so a mistyped URL gets a clear message rather
    # than urllib's "unknown url type".
    scheme = urllib.parse.urlsplit(req.full_url).scheme
    if scheme not in ("http", "https"):
        print(f"::error title=DefectDojo::refusing to open a {scheme or 'schemeless'} "
              "URL - DEFECTDOJO_URL must be http or https", file=sys.stderr)
        raise SystemExit(2)
    try:
        with _opener().open(req, timeout=300) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:2000]
        print(f"::error title=DefectDojo::{exc.code} {exc.reason}\n{detail}",
              file=sys.stderr)
        raise SystemExit(2) from exc
    except urllib.error.URLError as exc:
        print(f"::error title=DefectDojo::cannot reach {req.full_url}: {exc.reason}",
              file=sys.stderr)
        raise SystemExit(2) from exc


def post_import(url: str, token: str, fields: dict[str, str],
                payload: bytes) -> dict:
    endpoint = url.rstrip("/") + "/api/v2/import-scan/"
    ctype, body = _multipart(fields, "pipeline-findings.json", payload)
    req = urllib.request.Request(endpoint, data=body, method="POST")
    req.add_header("Authorization", f"Token {token}")
    req.add_header("Content-Type", ctype)
    req.add_header("Accept", "application/json")
    return _open(req)


def fetch_token(url: str, user: str, password: str) -> str:
    """Exchange credentials for an API token.

    Credentials arrive through the environment, never as arguments: an argument
    is visible in the process table to every other process on the machine.
    """
    endpoint = url.rstrip("/") + "/api/v2/api-token-auth/"
    body = urllib.parse.urlencode({"username": user, "password": password}).encode()
    req = urllib.request.Request(endpoint, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    token = _open(req).get("token")
    if not token:
        print("::error title=DefectDojo::no token in the response", file=sys.stderr)
        raise SystemExit(2)
    return token


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _render(args: argparse.Namespace) -> tuple[dict, list[str]]:
    policy = load_policy()
    findings, sources = collect(Path(args.reports))
    if not findings:
        print("no findings parsed - refusing to import an empty run "
              f"(did the scanners write to {args.reports}?)", file=sys.stderr)
        raise SystemExit(2)
    return build_payload(findings, policy, load_baseline(policy)), sources


def cmd_render(args: argparse.Namespace) -> int:
    payload, sources = _render(args)
    text = json.dumps(payload, indent=2) + "\n"
    Path(args.out).write_text(text, encoding="utf-8")
    accepted = sum(1 for f in payload["findings"] if f["risk_accepted"])
    print(f"wrote {len(payload['findings'])} findings to {args.out} "
          f"({accepted} baselined, {len(payload['findings']) - accepted} new)")
    for s in sources:
        print(f"  {s}")
    return 0


def cmd_push(args: argparse.Namespace) -> int:
    url = args.url or os.environ.get("DEFECTDOJO_URL", "")
    token = args.token or os.environ.get("DEFECTDOJO_TOKEN", "")
    if not url:
        print("DEFECTDOJO_URL must be set (or passed with --url)", file=sys.stderr)
        return 2
    # CI holds a long-lived token in a secret; the local instance holds a
    # generated admin password instead, so fall back to minting a token from it
    # rather than making the caller do it in shell.
    if not token and os.environ.get("DEFECTDOJO_PASSWORD"):
        token = fetch_token(url, os.environ.get("DEFECTDOJO_USER", "admin"),
                            os.environ["DEFECTDOJO_PASSWORD"])
    if not token:
        print("set DEFECTDOJO_TOKEN, or DEFECTDOJO_PASSWORD to mint one",
              file=sys.stderr)
        return 2

    payload, sources = _render(args)
    body = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    if args.out:
        Path(args.out).write_text(body.decode("utf-8"), encoding="utf-8")

    # auto_create_context lets one token bootstrap the product type, product and
    # engagement on first import, so a fresh DefectDojo needs no manual setup.
    # One engagement per branch keeps a pull request's findings from being read
    # as main's.
    fields = {
        "scan_type": "Generic Findings Import",
        "product_type_name": args.product_type,
        "product_name": args.product,
        "engagement_name": args.engagement,
        "auto_create_context": "true",
        "test_title": args.test_title,
        "scan_date": args.scan_date,
        "minimum_severity": "Info",
        # Everything arrives needing triage; per-finding `active` and
        # `risk_accepted` above are what actually distinguish the two states.
        "active": "true",
        "verified": "false",
        # Reimport semantics for the same engagement: a finding that stopped
        # being reported is closed rather than lingering as an open alert.
        "close_old_findings": "true",
        "apply_tags_to_findings": "false",
        "commit_hash": args.commit,
        "branch_tag": args.branch,
        "build_id": args.build_id,
        "version": args.commit[:12],
    }
    fields = {k: v for k, v in fields.items() if v}

    print(f"importing {len(payload['findings'])} findings into "
          f"{url.rstrip('/')} as {args.product} / {args.engagement}")
    for s in sources:
        print(f"  {s}")
    result = post_import(url, token, fields, body)
    stats = result.get("statistics") or {}
    print(f"  test id      {result.get('test_id')}")
    print(f"  engagement   {result.get('engagement_id')}")
    print(f"  product      {result.get('product_id')}")
    if stats:
        print("  statistics   " + json.dumps(stats))
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    url = args.url or os.environ.get("DEFECTDOJO_URL", "")
    user = os.environ.get("DEFECTDOJO_USER", "admin")
    password = os.environ.get("DEFECTDOJO_PASSWORD", "")
    if not url or not password:
        print("DEFECTDOJO_URL and DEFECTDOJO_PASSWORD must be set", file=sys.stderr)
        return 2
    # The token alone on stdout, so a caller can capture it: `TOKEN=$(... token)`.
    print(fetch_token(url, user, password))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--reports", default="reports")

    r = sub.add_parser("render", help="write a Generic Findings Import document")
    common(r)
    r.add_argument("--out", default="reports/defectdojo.json")
    r.set_defaults(func=cmd_render)

    p = sub.add_parser("push", help="render, then POST to DefectDojo")
    common(p)
    p.add_argument("--url", help="defaults to $DEFECTDOJO_URL")
    p.add_argument("--token", help="defaults to $DEFECTDOJO_TOKEN")
    p.add_argument("--product", default="PyGoat")
    p.add_argument("--product-type", default="Demo applications")
    p.add_argument("--engagement",
                   default=os.environ.get("GITHUB_REF_NAME") or "local")
    p.add_argument("--test-title", default="CI security pipeline")
    p.add_argument("--scan-date",
                   default=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    p.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    p.add_argument("--branch", default=os.environ.get("GITHUB_REF_NAME", ""))
    p.add_argument("--build-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    p.add_argument("--out", help="also keep the rendered document at this path")
    p.set_defaults(func=cmd_push)

    t = sub.add_parser("token", help="print an API token for $DEFECTDOJO_USER")
    t.add_argument("--url", help="defaults to $DEFECTDOJO_URL")
    t.set_defaults(func=cmd_token)

    args = ap.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
