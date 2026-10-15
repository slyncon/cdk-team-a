#!/usr/bin/env bash
# Capture each scanner exit separately. Findings are evaluated by security_gate.py.
set -euo pipefail
evidence=.build/security/real
inputs=.build/security-inputs
mkdir -p "$evidence"
: > "$evidence/status.tsv"
run() {
  local name=$1
  shift
  local status=0
  "$@" || status=$?
  printf '%s\t%s\n' "$name" "$status" >> "$evidence/status.tsv"
}
export SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
export SEMGREP_SETTINGS_FILE="$PWD/.build/security-tools/semgrep-settings.yml"
export SEMGREP_LOG_FILE="$PWD/.build/security-tools/semgrep.log"
run semgrep semgrep scan --oss-only --strict --metrics off --disable-version-check \
  --disable-nosem --config .build/semgrep-rules/python/lang/security \
  --json-output "$evidence/semgrep.json" --text --no-rewrite-rule-ids \
  handler app.py stack.py scripts
# Empty ignorefile disables all suppression in raw evidence, so KEV cannot be hidden.
run dependencies trivy fs --scanners vuln --include-dev-deps --list-all-pkgs \
  --ignorefile '' --format json --output "$evidence/dependencies.json" "$inputs/dependencies"
run iac trivy config --include-non-failures --ignorefile '' \
  --format json --output "$evidence/iac.json" "$inputs/iac"
run runtime trivy fs --scanners vuln --list-all-pkgs --ignorefile '' \
  --format json --output "$evidence/runtime.json" "$inputs/runtime"
for report in dependencies runtime; do
  run "$report-sbom" trivy convert --ignorefile '' --format cyclonedx \
    --output "$evidence/$report.cdx.json" "$evidence/$report.json"
done
for report in dependencies iac runtime; do
  # Native Trivy filtering for readable output only. The decision always uses raw JSON.
  run "$report-readable" trivy convert --ignorefile security/trivyignore.yaml \
    --show-suppressed --format table "$evidence/$report.json"
done
run kev curl --fail --silent --show-error --location --retry 3 --max-time 90 \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  --output "$evidence/kev.json"
