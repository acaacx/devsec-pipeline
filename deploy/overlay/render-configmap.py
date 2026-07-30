#!/usr/bin/env python3
"""Render deploy/k8s/20-configmap-settings.yaml from the shared settings overlay.

Kubernetes cannot mount a file out of the repository, so the overlay has to be
embedded in a ConfigMap. Compose can mount it directly. That leaves two copies
of security-relevant configuration, and two copies drift.

So the ConfigMap is generated from pygoat_deploy_settings.py rather than
maintained beside it. `make check-overlay` diffs this script's output against
the committed manifest and fails on any difference, which is the same guarantee
`make check-pins` gives for image digests.

    make sync-overlay    # regenerate after editing the overlay
    make check-overlay   # verify the committed manifest is current
"""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
OVERLAY = HERE / "pygoat_deploy_settings.py"
TARGET = HERE.parent / "k8s" / "20-configmap-settings.yaml"

HEADER = """---
# GENERATED FILE - do not edit.
#
# Rendered from deploy/overlay/pygoat_deploy_settings.py by
# deploy/overlay/render-configmap.py. Edit the overlay and run
# `make sync-overlay`; `make check-overlay` fails if the two disagree.
#
# The same overlay is bind-mounted by deploy/compose/docker-compose.dast.yml, so
# the DAST stage exercises exactly the settings this manifest deploys. See the
# overlay's docstring for why it exists at all.
apiVersion: v1
kind: ConfigMap
metadata:
  name: pygoat-settings
  namespace: pygoat
  labels:
    app.kubernetes.io/name: pygoat
data:
"""


def render() -> str:
    body = OVERLAY.read_text(encoding="utf-8")
    # A literal block scalar keeps the source readable in `kubectl get -o yaml`.
    # Blank lines must stay genuinely blank: trailing indentation on an empty
    # line is legal YAML but shows up as trailing whitespace in the manifest.
    indented = "".join(
        f"    {line}\n" if line.strip() else "\n" for line in body.splitlines()
    )
    return f"{HEADER}  {OVERLAY.name}: |\n{indented}"


def main(argv: list[str]) -> int:
    text = render()
    if "--write" in argv:
        TARGET.write_text(text, encoding="utf-8")
        print(f"wrote {TARGET.relative_to(HERE.parent.parent)}")
        return 0
    if "--check" in argv:
        current = TARGET.read_text(encoding="utf-8") if TARGET.is_file() else ""
        if current == text:
            print("overlay and ConfigMap agree")
            return 0
        print(
            f"DRIFT: {TARGET} is not what {OVERLAY.name} renders to. "
            "Run `make sync-overlay`.",
            file=sys.stderr,
        )
        return 1
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
