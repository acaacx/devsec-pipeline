# Local developer experience for the security pipeline.
#
# Every target runs the *same digest-pinned container* as CI, with the same
# flags, so a clean `make scan` means a clean pipeline. Nothing is installed on
# the host: Docker and Python 3 are the only prerequisites.
#
# Image digests are duplicated from .github/workflows/ci.yml. `make check-pins`
# verifies the two have not drifted.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# --- Scanner images, digest-pinned (tag in the comment is the version) --------
IMG_PYTHON   := python@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93                  # python:3.11-slim
IMG_SEMGREP  := semgrep/semgrep@sha256:65dcd4408adda7c183a6b4550cb1e9b19f7f627a6fbb7e0559bd466bedc44d7b          # v1.172.0
IMG_TRIVY    := aquasec/trivy@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f            # v0.72.0
IMG_GITLEAKS := zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f     # v8.30.1
IMG_HADOLINT := hadolint/hadolint@sha256:7aba693c1442eb31c0b015c129697cb3b6cb7da589d85c7562f9deb435a6657c        # v2.14.0-alpine
IMG_SYFT     := anchore/syft@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026             # v1.50.0
IMG_COSIGN   := gcr.io/projectsigstore/cosign@sha256:d91bc4e7e95e8d2f549c747a72dc174f90579e410a1695f57f686674f84ce849  # v3.1.2
IMG_CHECKOV   := bridgecrew/checkov@sha256:c64ffb6d6fc8087c896341a2c697770a04a1cf558db04fa7b8129d8ca6bce336          # 3.3.8
IMG_CONFTEST  := openpolicyagent/conftest@sha256:5fd81e332d7e4bc01daf3ef35371800a9a9720a30c0c37a78de0c5fbe4b6d622    # v0.68.2 (OPA 1.15.2)
IMG_TERRAFORM := hashicorp/terraform@sha256:7ae513256f7ce67879e218ae8593d6fbe216ec9e123abe6c94e4e10704857963         # 1.15.8
IMG_ZAP       := zaproxy/zap-stable@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2           # v2.17.0

# Local image tag mirrors CI: the commit SHA, never `latest`.
GIT_SHA      := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
IMAGE_LOCAL  := pygoat-local:$(GIT_SHA)

BANDIT_VERSION    := 1.9.4
PIP_AUDIT_VERSION := 2.10.1

REPORT_DIR := reports
CACHE_PIP  := .cache/pip
CACHE_TRIVY := .trivycache
ROOT := $(shell pwd)

# Stage 5 - scratch state for the ephemeral DAST deployment. Under reports/ so
# `make clean` and .gitignore already cover it; world-writable because the
# container runs as UID 10001 and Compose has no equivalent of fsGroup.
DAST_STATE   := $(ROOT)/$(REPORT_DIR)/.dast
DAST_COMPOSE := docker compose -f deploy/compose/docker-compose.dast.yml
DAST_TARGET  := http://web:8000
# Ceiling on the spider, not a target: against this application it finishes in
# well under a minute, and raising the ceiling to 4 changed nothing. It is here
# so a pathological crawl cannot hang the pipeline.
#
# The crawl is concurrent and the passive-scan queue drains asynchronously, so
# which URLs each alert is attached to varies from run to run. That is why
# parse_zap in .security/gate.py keeps URLs out of the fingerprint - see its
# docstring.
DAST_SPIDER_MINUTES := 2

# Reused container invocations.
DOCKER_PY := docker run --rm -v "$(ROOT)":/src -v "$(ROOT)/$(CACHE_PIP)":/root/.cache/pip -w /src $(IMG_PYTHON)
DOCKER_TRIVY := docker run --rm -v "$(ROOT)":/src -v "$(ROOT)/$(CACHE_TRIVY)":/root/.cache/trivy -w /src $(IMG_TRIVY)
DOCKER_GITLEAKS := docker run --rm -v "$(ROOT)":/repo -w /repo $(IMG_GITLEAKS)
DOCKER_CONFTEST := docker run --rm -v "$(ROOT)":/project -w /project $(IMG_CONFTEST)
# AWS_PROFILE and AWS_REGION are emptied so nothing on the host can point this
# at a real account. The two key variables are populated with obvious mock
# values instead of being emptied, because the provider requires the fields even
# though every call that would use them is skipped - see deploy/terraform/
# provider.tf. They live here rather than in the .tf file so that Semgrep's
# hardcoded-credential rule keeps its meaning.
DOCKER_TERRAFORM := docker run --rm -v "$(ROOT)/deploy/terraform":/tf -w /tf \
	-e AWS_ACCESS_KEY_ID=mock-access-key-not-a-credential \
	-e AWS_SECRET_ACCESS_KEY=mock-secret-key-not-a-credential \
	-e AWS_PROFILE= -e AWS_REGION= $(IMG_TERRAFORM)

# Stage 6 - triage. The local DefectDojo instance is not part of the pipeline;
# see deploy/compose/docker-compose.defectdojo.yml for why its images are pinned
# but absent from check-pins.
DD_COMPOSE := docker compose -f deploy/compose/docker-compose.defectdojo.yml
# Generated per machine, never committed: reports/ is gitignored in full.
DD_ENV     := $(ROOT)/$(REPORT_DIR)/.defectdojo.env
DD_PORT    ?= 8080
DD_URL     := http://127.0.0.1:$(DD_PORT)

.PHONY: help dirs scan scan-sast scan-secrets scan-deps scan-dockerfile scan-image scan-iac policy-test tf-validate build sbom dast dast-up dast-down dast-logs gate baseline-update defectdojo-up defectdojo-token defectdojo-import defectdojo-down defectdojo-destroy lint check-pins check-overlay sync-overlay clean

help: ## Show this help
	@echo "Security pipeline - local targets"
	@echo
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-18s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Reports land in ./$(REPORT_DIR) (gitignored). Accepted findings live in"
	@echo ".security/baseline/ - see .security/POLICY.md before editing them."

dirs:
	@mkdir -p $(REPORT_DIR) $(CACHE_PIP) $(CACHE_TRIVY)

# -----------------------------------------------------------------------------
# Stage 1 - Code
# -----------------------------------------------------------------------------
scan-secrets: dirs ## Gitleaks over full git history (redacted SARIF + local-only JSON)
	@echo ">> gitleaks (full history)"
	@$(DOCKER_GITLEAKS) git --config /repo/.gitleaks.toml --report-format sarif \
		--report-path $(REPORT_DIR)/gitleaks.sarif --redact --exit-code 0 .
	@# Unredacted output is used only to compute irreversible fingerprints. It is
	@# gitignored and must never be uploaded or committed - see .security/POLICY.md.
	@$(DOCKER_GITLEAKS) git --config /repo/.gitleaks.toml --report-format json \
		--report-path $(REPORT_DIR)/.gitleaks-unredacted.json --exit-code 0 .

scan-sast: dirs ## Bandit + Semgrep (identical flags to CI)
	@echo ">> bandit"
	@$(DOCKER_PY) sh -c 'set -e; \
		pip install -q "bandit[sarif]==$(BANDIT_VERSION)"; \
		set +e; \
		bandit -ll -ii -r . -f json  -o $(REPORT_DIR)/bandit.json  -q; json_rc=$$?; \
		bandit -ll -ii -r . -f sarif -o $(REPORT_DIR)/bandit.sarif -q; sarif_rc=$$?; \
		if [ "$$json_rc" -gt 1 ] || [ "$$sarif_rc" -gt 1 ]; then echo "bandit scanner error"; exit 2; fi; \
		exit 0'
	@echo ">> semgrep (p/python, p/django, p/owasp-top-ten)"
	@docker run --rm -v "$(ROOT)":/src -w /src $(IMG_SEMGREP) \
		semgrep scan --config p/python --config p/django --config p/owasp-top-ten \
		--sarif --output $(REPORT_DIR)/semgrep.sarif --metrics off --exclude $(REPORT_DIR)
	@test -s $(REPORT_DIR)/semgrep.sarif || { echo "semgrep produced no SARIF"; exit 2; }

# -----------------------------------------------------------------------------
# Stage 2 - Dependencies
# -----------------------------------------------------------------------------
scan-deps: dirs ## pip-audit + Trivy filesystem scan (vulns, licences, secrets)
	@echo ">> pip-audit"
	@# libpq-dev is required because psycopg2's sdist needs pg_config to expose
	@# metadata; substituting psycopg2-binary would audit a package the app does
	@# not install.
	@$(DOCKER_PY) sh -c 'set -e; \
		apt-get -qq update >/dev/null; \
		apt-get -qq install -y --no-install-recommends gcc libpq-dev python3-dev >/dev/null; \
		pip install -q "pip-audit==$(PIP_AUDIT_VERSION)"; \
		set +e; \
		pip-audit -r requirements.txt -f json -o $(REPORT_DIR)/pip-audit.json --progress-spinner off; \
		rc=$$?; \
		if [ "$$rc" -gt 1 ]; then exit "$$rc"; fi; \
		test -s $(REPORT_DIR)/pip-audit.json'
	@echo ">> trivy fs"
	@$(DOCKER_TRIVY) fs --scanners vuln,license,secret --format json \
		--output $(REPORT_DIR)/trivy-fs.json --skip-dirs $(REPORT_DIR) \
		--skip-dirs $(CACHE_TRIVY) --skip-dirs .cache --exit-code 0 .
	@$(DOCKER_TRIVY) fs --scanners vuln,license,secret --format sarif \
		--output $(REPORT_DIR)/trivy-fs.sarif --skip-dirs $(REPORT_DIR) \
		--skip-dirs $(CACHE_TRIVY) --skip-dirs .cache --exit-code 0 .

# -----------------------------------------------------------------------------
# Stage 3 - Build and package
# -----------------------------------------------------------------------------
build: ## Build the image, tagged with the current commit SHA (never `latest`)
	@echo ">> docker build $(IMAGE_LOCAL)"
	@docker build -f Dockerfile -t $(IMAGE_LOCAL) .
	@docker image inspect $(IMAGE_LOCAL) --format 'built {{.Id}} ({{.Size}} bytes)'

scan-dockerfile: dirs ## Hadolint over the Dockerfile
	@echo ">> hadolint"
	@docker run --rm -i $(IMG_HADOLINT) hadolint --no-color --format sarif - \
		< Dockerfile > $(REPORT_DIR)/hadolint.sarif || true
	@docker run --rm -i $(IMG_HADOLINT) hadolint --no-color --format json - \
		< Dockerfile > $(REPORT_DIR)/hadolint.json || true
	@test -s $(REPORT_DIR)/hadolint.sarif || { echo "hadolint produced no SARIF"; exit 2; }
	@docker run --rm -i $(IMG_HADOLINT) hadolint --no-color - < Dockerfile || true

scan-image: dirs scan-dockerfile build ## Hadolint + Trivy image scan of the built image
	@echo ">> trivy image"
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		-v "$(ROOT)/$(CACHE_TRIVY)":/root/.cache/trivy -v "$(ROOT)/$(REPORT_DIR)":/out \
		$(IMG_TRIVY) image --scanners vuln,secret --format json \
		--output /out/trivy-image.json --exit-code 0 $(IMAGE_LOCAL)
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		-v "$(ROOT)/$(CACHE_TRIVY)":/root/.cache/trivy -v "$(ROOT)/$(REPORT_DIR)":/out \
		$(IMG_TRIVY) image --scanners vuln,secret --format sarif \
		--output /out/trivy-image.sarif --exit-code 0 $(IMAGE_LOCAL)
	@# Docker Scout needs a Docker Hub account for its advisory DB, so it is not
	@# part of the local flow. CI runs it when DOCKERHUB_* secrets exist.

sbom: dirs build ## Generate CycloneDX + SPDX SBOMs for the built image
	@mkdir -p sbom
	@echo ">> syft"
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		-v "$(ROOT)/sbom":/out $(IMG_SYFT) $(IMAGE_LOCAL) \
		-o cyclonedx-json=/out/sbom.cdx.json -o spdx-json=/out/sbom.spdx.json
	@python3 -c "import json; \
c=json.load(open('sbom/sbom.cdx.json')); s=json.load(open('sbom/sbom.spdx.json')); \
print('cyclonedx', c.get('specVersion'), len(c.get('components', [])), 'components'); \
print('spdx', s.get('spdxVersion'), len(s.get('packages', [])), 'packages')"

# -----------------------------------------------------------------------------
# Stage 4 - Provision (infrastructure as code)
# -----------------------------------------------------------------------------
policy-test: ## Run the Rego unit tests for policy/ (must pass before the policy is trusted)
	@echo ">> conftest verify (rego unit tests)"
	@$(DOCKER_CONFTEST) verify --policy policy

tf-validate: ## terraform fmt/validate/plan for deploy/terraform - never `apply`
	@echo ">> terraform init"
	@$(DOCKER_TERRAFORM) init -input=false -no-color >/dev/null
	@echo ">> terraform fmt -check"
	@$(DOCKER_TERRAFORM) fmt -check -recursive -no-color
	@echo ">> terraform validate"
	@$(DOCKER_TERRAFORM) validate -no-color
	@# `plan` proves the config is not merely syntactically valid but resolvable,
	@# with every AWS_* variable emptied above so it cannot reach a real account.
	@# There is deliberately no `apply` target: see deploy/terraform/versions.tf.
	@echo ">> terraform plan (no credentials, never applied)"
	@$(DOCKER_TERRAFORM) plan -input=false -no-color -lock=false | tail -5

scan-iac: dirs check-overlay policy-test ## Checkov + Trivy config + Conftest over deploy/ and policy/
	@echo ">> checkov (kubernetes + terraform)"
	@# Checkov exits non-zero when it finds anything. Findings are the gate's
	@# business, not this step's, so only a genuine crash (exit >1) fails here -
	@# the same rule Bandit gets in scan-sast.
	@docker run --rm -v "$(ROOT)":/src -w /src --entrypoint checkov $(IMG_CHECKOV) \
		--directory deploy --framework kubernetes terraform \
		--output json --quiet --compact > $(REPORT_DIR)/checkov.json; \
		rc=$$?; if [ "$$rc" -gt 1 ]; then echo "checkov scanner error ($$rc)"; exit 2; fi
	@test -s $(REPORT_DIR)/checkov.json || { echo "checkov produced no report"; exit 2; }
	@echo ">> trivy config"
	@# --config-data supplies the trusted-registry allowlist for KSV0125; see
	@# policy/trivy-data/ksv0125.json.
	@$(DOCKER_TRIVY) config deploy --config-data policy/trivy-data \
		--format json --output $(REPORT_DIR)/trivy-config.json --exit-code 0
	@$(DOCKER_TRIVY) config deploy --config-data policy/trivy-data \
		--format sarif --output $(REPORT_DIR)/trivy-config.sarif --exit-code 0
	@echo ">> conftest (OPA policy over deploy/k8s)"
	@$(DOCKER_CONFTEST) test --policy policy --output json deploy/k8s \
		> $(REPORT_DIR)/conftest.json || true
	@test -s $(REPORT_DIR)/conftest.json || { echo "conftest produced no report"; exit 2; }
	@$(MAKE) --no-print-directory tf-validate

# -----------------------------------------------------------------------------
# Stage 5 - Deploy and DAST
#
# The first stage that runs the application rather than reading it. Everything
# before this point is static: a scanner's opinion about code it never executed.
# ZAP talks to a live PyGoat over HTTP and reports what the server actually did.
#
# The deployment mirrors deploy/k8s/30-deployment.yaml - same image, same
# settings overlay, same read-only root filesystem, same unprivileged UID - so a
# constraint that breaks the app in production breaks it here, in CI, first.
# -----------------------------------------------------------------------------
DAST_ENV := DAST_IMAGE=$(IMAGE_LOCAL) DAST_STATE=$(DAST_STATE)

dast-up: ## Bring the ephemeral hardened deployment up and wait for it to be healthy
	@# No `build` prerequisite: CI overrides IMAGE_LOCAL with the image Stage 3
	@# handed it and must not rebuild. The compose file sets pull_policy: never,
	@# so a missing image would otherwise surface as a confusing registry error.
	@docker image inspect $(IMAGE_LOCAL) >/dev/null 2>&1 \
		|| { echo "$(IMAGE_LOCAL) is not present locally - run \`make build\`"; exit 1; }
	@# Idempotent: a deployment left running by an interrupted scan still has the
	@# scratch directory bind-mounted, so it has to go before that is deleted.
	@$(MAKE) --no-print-directory dast-down
	@rm -rf $(DAST_STATE)
	@mkdir -p $(DAST_STATE)/data
	@# The bind source must exist as a *file*: Docker creates a directory for a
	@# missing bind source, and Python's logging module then fails to open it.
	@touch $(DAST_STATE)/data/app.log
	@# The container runs as UID 10001 and Compose has no equivalent of fsGroup,
	@# so the scratch directory has to be writable by an unrelated UID. Confined
	@# to reports/.dast; nothing else in the tree is loosened.
	@chmod -R 777 $(DAST_STATE)
	@echo ">> docker compose up (hardened, mirrors deploy/k8s)"
	@$(DAST_ENV) $(DAST_COMPOSE) up -d --wait \
		|| { echo "deployment never became healthy:"; \
		     $(DAST_ENV) $(DAST_COMPOSE) logs --tail 60; exit 1; }

dast-logs: ## Print the DAST deployment's container logs
	@$(DAST_ENV) $(DAST_COMPOSE) logs --no-color --timestamps 2>&1 || true

dast-down: ## Tear the DAST deployment down, with its network and volumes
	@$(DAST_ENV) $(DAST_COMPOSE) down --remove-orphans --volumes --timeout 10 \
		>/dev/null 2>&1 || true

dast: dirs build ## Deploy the built image and run a ZAP baseline scan against it
	@# Teardown has to happen whether the scan succeeded, failed or never
	@# started, so the whole sequence lives in one shell with a single exit path.
	@rc=0; \
	if ! $(MAKE) --no-print-directory dast-up; then \
		rc=2; \
	else \
		echo ">> zap baseline against $(DAST_TARGET)"; \
		docker run --rm --network pygoat-dast \
			-v "$(DAST_STATE)":/zap/wrk:rw \
			-v "$(ROOT)/.security/zap":/zap/conf:ro \
			$(IMG_ZAP) zap-baseline.py -t $(DAST_TARGET) \
			-m $(DAST_SPIDER_MINUTES) -c /zap/conf/rules.tsv \
			-J zap.json -r zap.html -I; \
		zrc=$$?; \
		if [ "$$zrc" -gt 2 ]; then echo "zap scanner error ($$zrc)"; rc=2; fi; \
	fi; \
	$(MAKE) --no-print-directory dast-down; \
	exit $$rc
	@# Exit 0 (nothing tripped), 1 (a FAIL rule fired) and 2 (warnings present)
	@# all mean ZAP ran and found things, which is the gate's business, not this
	@# step's. Only 3 and above is ZAP failing to run - handled above. An empty
	@# report means it produced nothing at all, which is a scanner error.
	@test -s $(DAST_STATE)/zap.json || { echo "zap produced no report"; exit 2; }
	@cp $(DAST_STATE)/zap.json $(DAST_STATE)/zap.html $(REPORT_DIR)/
	@python3 -c "import json; \
d=json.load(open('$(REPORT_DIR)/zap.json')); \
a=[x for s in d.get('site', []) for x in s.get('alerts', [])]; \
print('zap', d.get('@version'), len(a), 'alert type(s),', \
      sum(int(x.get('count', 0)) for x in a), 'instance(s)')"

# -----------------------------------------------------------------------------
# Aggregate
# -----------------------------------------------------------------------------
scan: scan-secrets scan-sast scan-deps scan-image scan-iac dast gate ## Run every scanner, then the gate

gate: ## Evaluate existing reports against .security/policy.json
	@python3 .security/gate.py gate --reports $(REPORT_DIR)

baseline-update: ## Re-run all scanners, regenerate .security/baseline/, print a diff
	@# dast is included: ZAP's alerts are properties of the HTTP responses, not
	@# of the runner's architecture, so unlike trivy-image they baseline
	@# correctly from a laptop.
	@$(MAKE) --no-print-directory scan-secrets scan-sast scan-deps scan-iac dast
	@python3 .security/gate.py baseline --reports $(REPORT_DIR)
	@echo
	@echo "NOTE: trivy-image is baselined from CI, not from here - an arm64 laptop"
	@echo "cannot see the amd64-only packages the gate will meet on a CI runner."
	@echo "See .security/POLICY.md section 4."

# -----------------------------------------------------------------------------
# Triage - local DefectDojo
#
# The gate decides whether a build passes; DefectDojo is where a human decides
# what deserves a baseline entry. Nothing in CI depends on these targets.
# -----------------------------------------------------------------------------
$(DD_ENV): | dirs
	@# Upstream's compose file ships working values for these; they are published,
	@# so using them would put a known encryption key in a security repository.
	@# Generated once per machine instead, into a gitignored file.
	@echo ">> generating $(DD_ENV)"
	@python3 -c "import secrets, string; \
a = string.ascii_letters + string.digits; \
print('DD_SECRET_KEY=' + secrets.token_urlsafe(48)); \
print('DD_CREDENTIAL_AES_256_KEY=' + ''.join(secrets.choice(a) for _ in range(32))); \
print('DD_DATABASE_PASSWORD=' + ''.join(secrets.choice(a) for _ in range(32))); \
print('DD_ADMIN_PASSWORD=' + ''.join(secrets.choice(a) for _ in range(24)))" > $(DD_ENV)
	@chmod 600 $(DD_ENV)

defectdojo-up: $(DD_ENV) ## Bring up a local DefectDojo for triage (first run migrates, ~2 min)
	@set -a; . $(DD_ENV); set +a; DD_PORT=$(DD_PORT) $(DD_COMPOSE) up -d
	@echo ">> waiting for $(DD_URL) (the initializer migrates the database first)"
	@# No compose healthcheck: the upstream images define none, so `up --wait`
	@# would return as soon as the containers were running - which is minutes
	@# before Django serves anything. Polling from the host also proves the
	@# published port works, not just the container.
	@for i in $$(seq 1 90); do \
		if curl -fsS -o /dev/null "$(DD_URL)/login?next=/"; then \
			echo "DefectDojo is up at $(DD_URL) - user admin, credentials in $(DD_ENV)"; \
			exit 0; \
		fi; \
		sleep 5; \
	done; \
	echo "DefectDojo did not come up within 450s; last 40 lines:"; \
	set -a; . $(DD_ENV); set +a; $(DD_COMPOSE) logs --tail 40; exit 1

defectdojo-token: $(DD_ENV) ## Print an API token for the local instance
	@set -a; . $(DD_ENV); set +a; \
	export DEFECTDOJO_URL=$(DD_URL) DEFECTDOJO_USER=admin; \
	export DEFECTDOJO_PASSWORD=$$DD_ADMIN_PASSWORD; \
	python3 .security/defectdojo.py token

defectdojo-import: $(DD_ENV) ## Push the findings in reports/ into the local DefectDojo
	@# Credentials go through the environment, not the command line, so they do
	@# not appear in the process table. `push` mints its own token from them.
	@set -a; . $(DD_ENV); set +a; \
	export DEFECTDOJO_URL=$(DD_URL) DEFECTDOJO_USER=admin; \
	export DEFECTDOJO_PASSWORD=$$DD_ADMIN_PASSWORD; \
	python3 .security/defectdojo.py push --reports $(REPORT_DIR) \
		--out $(REPORT_DIR)/defectdojo.json

# The compose file declares its secrets as required (`${VAR:?}`), so teardown
# has to satisfy the interpolation even when the env file is already gone -
# otherwise a half-destroyed stack cannot be cleaned up at all.
DD_ENV_OR_STUBS = set -a; [ -f $(DD_ENV) ] && . $(DD_ENV); \
	: $${DD_SECRET_KEY:=unset} $${DD_CREDENTIAL_AES_256_KEY:=unset} \
	  $${DD_DATABASE_PASSWORD:=unset} $${DD_ADMIN_PASSWORD:=unset}; set +a

defectdojo-down: ## Stop DefectDojo, keeping the database and its triage decisions
	@$(DD_ENV_OR_STUBS); $(DD_COMPOSE) down --remove-orphans

defectdojo-destroy: ## Stop DefectDojo and delete its volumes and generated secrets
	@$(DD_ENV_OR_STUBS); \
		$(DD_COMPOSE) down --remove-orphans --volumes
	@rm -f $(DD_ENV)
	@echo "removed the DefectDojo volumes and $(DD_ENV)"

# -----------------------------------------------------------------------------
# Pipeline hygiene
# -----------------------------------------------------------------------------
lint: ## actionlint + yamllint over the workflows and all YAML
	@command -v actionlint >/dev/null || { echo "actionlint missing: brew install actionlint"; exit 127; }
	@command -v yamllint   >/dev/null || { echo "yamllint missing: brew install yamllint"; exit 127; }
	@actionlint -no-color -oneline
	@yamllint -s .
	@echo "actionlint + yamllint clean"

check-pins: ## Verify Makefile image digests match .github/workflows/ci.yml
	@fail=0; \
	for pin in $(IMG_PYTHON) $(IMG_SEMGREP) $(IMG_TRIVY) $(IMG_GITLEAKS) \
	           $(IMG_HADOLINT) $(IMG_SYFT) $(IMG_COSIGN) \
	           $(IMG_CHECKOV) $(IMG_CONFTEST) $(IMG_TERRAFORM) $(IMG_ZAP); do \
		if ! grep -qF "$$pin" .github/workflows/ci.yml; then \
			echo "DRIFT: $$pin is not in .github/workflows/ci.yml"; fail=1; \
		fi; \
	done; \
	if [ "$$fail" = 0 ]; then echo "image pins match CI"; else exit 1; fi

check-overlay: ## Verify the settings ConfigMap still matches deploy/overlay/
	@# The Kubernetes ConfigMap and the DAST deployment share one settings
	@# overlay. Kubernetes cannot mount a file from the repository, so the
	@# ConfigMap embeds a copy - and a copy drifts. Same guarantee as check-pins.
	@python3 deploy/overlay/render-configmap.py --check

sync-overlay: ## Regenerate the settings ConfigMap from deploy/overlay/
	@python3 deploy/overlay/render-configmap.py --write

clean: ## Remove generated reports and scanner caches
	@rm -rf $(REPORT_DIR) $(CACHE_PIP) $(CACHE_TRIVY)
	@echo "removed $(REPORT_DIR), $(CACHE_PIP), $(CACHE_TRIVY)"
