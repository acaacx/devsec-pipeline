"""Deployment-time settings overlay for PyGoat.

Two properties of the application make it unable to run under a hardened
runtime as shipped, and neither can be fixed in the image without editing app
code - out of scope by this repository's own convention, because PyGoat's
behaviour is the teaching material. Both are corrected here, at the deployment
boundary, which is where environment-specific configuration belongs:

  1. DATABASES.NAME is hardcoded to BASE_DIR/db.sqlite3 = /app/db.sqlite3. A
     read-only root filesystem makes /app unwritable, and sqlite creates its
     rollback journal *beside* the database file, so mounting a single writable
     file over the database is not enough - it needs a writable directory.

  2. ALLOWED_HOSTS is ['pygoat.herokuapp.com', '0.0.0.0.']. Anything that
     addresses the container by a name or IP not in that list - a kubelet
     httpGet probe, a Compose service alias, a DAST scanner - gets HTTP 400
     DisallowedHost, so readiness never succeeds.

Both values are read from the environment, so this one module serves every
deployment target. It is the single source of truth for the overlay:

  - deploy/k8s/20-configmap-settings.yaml embeds it verbatim in a ConfigMap,
    because Kubernetes has no way to mount a file from the repository.
  - deploy/compose/docker-compose.dast.yml bind-mounts this file directly.

`make check-overlay` fails if the embedded copy drifts from this file, so DAST
cannot end up exercising different settings from the ones that get deployed.

gunicorn puts its working directory on sys.path, so `pygoat.settings` resolves
from /app while this module is found on PYTHONPATH=/config. pygoat/wsgi.py
selects the settings module with os.environ.setdefault, so the deployment's
DJANGO_SETTINGS_MODULE takes precedence over the baked-in default.
"""
import os

from pygoat.settings import *  # noqa: F401,F403

# Relocate sqlite onto the writable volume. See the module docstring.
_DATA_DIR = os.environ.get("PYGOAT_DATA_DIR", "/data")
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(_DATA_DIR, "db.sqlite3"),
    }
}

# Explicit host allowlist rather than '*', so probes and scanners are answered
# without opening the application to Host-header abuse.
ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get("PYGOAT_ALLOWED_HOSTS", "").split(",")
    if h.strip()
] or ["localhost"]
