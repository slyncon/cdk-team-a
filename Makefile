# Shared local/Actions commands. Scanner outcomes remain evidence for the policy gate.
SHELL := /bin/sh
.SHELLFLAGS := -eu -c
.DEFAULT_GOAL := help
PYTHON ?= python
SCENARIO ?= real
EVIDENCE := .build/security/real
INPUTS := .build/security-inputs
export PATH := $(CURDIR)/.build/security-tools:$(CURDIR)/node_modules/.bin:$(PATH)
export SEMGREP_SETTINGS_FILE := $(CURDIR)/.build/security-tools/semgrep-settings.yml
export SEMGREP_LOG_FILE := $(CURDIR)/.build/security-tools/semgrep.log
export SEMGREP_SEND_METRICS := off
export SEMGREP_ENABLE_VERSION_CHECK := 0
export TRIVY_CACHE_DIR := $(CURDIR)/.build/trivy-cache

.PHONY: help install lint test audit synth validate security-tools security-prepare \
        semgrep trivy-dependencies trivy-iac trivy-runtime sbom reports kev security-decision security
help:
	@echo 'make validate | security-tools | security | security-decision SCENARIO=clean'

install:
	$(PYTHON) -m pip install --require-hashes -r requirements.lock
	$(PYTHON) -m pip install --no-deps --no-build-isolation -r requirements.txt
	$(PYTHON) -m pip check
	npm ci

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m bandit -r handler app.py stack.py scripts -ll

test:
	$(PYTHON) -m pytest -q

audit:
	$(PYTHON) -m pip_audit --require-hashes --disable-pip -r requirements.lock
	npm audit --audit-level=high

synth:
	cdk synth
	cdk-launchpad-validate .build/cdk.out
	$(PYTHON) scripts/check_assembly.py .build/cdk.out

validate: lint test audit synth

security-tools:
	mkdir -p .build/security-tools .build/semgrep-rules
	curl -fsSL --retry 3 https://github.com/aquasecurity/trivy/releases/download/v0.76.0/trivy_0.76.0_Linux-64bit.tar.gz -o .build/security-tools/trivy.tar.gz
	echo 'e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7  .build/security-tools/trivy.tar.gz' | sha256sum -c -
	tar -xzf .build/security-tools/trivy.tar.gz -C .build/security-tools trivy
	trivy --version
	$(PYTHON) -m pip install --disable-pip-version-check 'semgrep==1.181.0'
	semgrep --version
	curl -fsSL --retry 3 https://codeload.github.com/semgrep/semgrep-rules/tar.gz/9bbf021d0acffa3095fcffd17b2bc7787eb4796d -o .build/security-tools/rules.tar.gz
	echo 'b6cb72d07e060fe03e890bb88d40e5c1f2a177780dbb5be1c3b01e5509fd9cec  .build/security-tools/rules.tar.gz' | sha256sum -c -
	tar -xzf .build/security-tools/rules.tar.gz --strip-components=1 -C .build/semgrep-rules

security-prepare:
	$(PYTHON) scripts/security_prepare.py

# Record the real exit code, including a missing executable or failed conversion.
# Return failure to Actions as well; later steps still collect evidence with always().
define scan
	@mkdir -p $(EVIDENCE)
	status=0; $(2) || status=$$?; printf '%s\t%s\n' '$(1)' "$$status" >> $(EVIDENCE)/status.tsv; exit "$$status"
endef

semgrep:
	$(call scan,semgrep,semgrep scan --oss-only --strict --metrics off --disable-version-check \
	  --disable-nosem --config .build/semgrep-rules/python/lang/security \
	  --json-output $(EVIDENCE)/semgrep.json --text --no-rewrite-rule-ids handler app.py stack.py scripts)

trivy-dependencies:
	$(call scan,dependencies,trivy fs --scanners vuln --include-dev-deps --list-all-pkgs \
	  --ignorefile '' --format json --output $(EVIDENCE)/dependencies.json $(INPUTS)/dependencies)

trivy-iac:
	$(call scan,iac,trivy config --include-non-failures --ignorefile '' \
	  --format json --output $(EVIDENCE)/iac.json $(INPUTS)/iac)

trivy-runtime:
	$(call scan,runtime,trivy fs --scanners vuln --list-all-pkgs --ignorefile '' \
	  --format json --output $(EVIDENCE)/runtime.json $(INPUTS)/runtime)

sbom:
	$(call scan,dependencies-sbom,trivy convert --ignorefile '' --format cyclonedx \
	  --output $(EVIDENCE)/dependencies.cdx.json $(EVIDENCE)/dependencies.json)
	$(call scan,runtime-sbom,trivy convert --ignorefile '' --format cyclonedx \
	  --output $(EVIDENCE)/runtime.cdx.json $(EVIDENCE)/runtime.json)

reports:
	$(call scan,dependencies-readable,trivy convert --ignorefile security/trivyignore.yaml --show-suppressed --format table $(EVIDENCE)/dependencies.json)
	$(call scan,iac-readable,trivy convert --ignorefile security/trivyignore.yaml --show-suppressed --format table $(EVIDENCE)/iac.json)
	$(call scan,runtime-readable,trivy convert --ignorefile security/trivyignore.yaml --show-suppressed --format table $(EVIDENCE)/runtime.json)

kev:
	$(call scan,kev,curl -fsSL --retry 3 --max-time 90 \
	  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o $(EVIDENCE)/kev.json)

security-decision:
	$(PYTHON) scripts/security_gate.py --scenario "$(SCENARIO)"

# Run sequentially: prepare clears stale inputs; -k collects reports after failures.
security:
	$(MAKE) security-prepare
	scans=0; $(MAKE) -j1 -k semgrep trivy-dependencies trivy-iac trivy-runtime sbom reports kev || scans=$$?; \
	  decision=0; $(MAKE) security-decision || decision=$$?; test $$scans -eq 0 -a $$decision -eq 0
