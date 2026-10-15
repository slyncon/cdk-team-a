#!/usr/bin/env bash
# Official pinned Linux amd64 release + SHA-256, and immutable official Semgrep rules.
set -euo pipefail
mkdir -p .build/security-tools .build/semgrep-rules
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/aquasecurity/trivy/releases/download/v0.76.0/trivy_0.76.0_Linux-64bit.tar.gz \
  --output .build/security-tools/trivy.tar.gz
echo 'e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7  .build/security-tools/trivy.tar.gz' | sha256sum -c -
tar -xzf .build/security-tools/trivy.tar.gz -C .build/security-tools trivy
export PATH="$PWD/.build/security-tools:$PATH"
if [[ -n "${GITHUB_PATH:-}" ]]; then echo "$PWD/.build/security-tools" >> "$GITHUB_PATH"; fi
trivy --version
python -m pip install --disable-pip-version-check 'semgrep==1.181.0'
export SEMGREP_SETTINGS_FILE="$PWD/.build/security-tools/semgrep-settings.yml"
export SEMGREP_LOG_FILE="$PWD/.build/security-tools/semgrep.log"
semgrep --version
curl --fail --silent --show-error --location --retry 3 \
  https://codeload.github.com/semgrep/semgrep-rules/tar.gz/9bbf021d0acffa3095fcffd17b2bc7787eb4796d \
  --output .build/security-tools/rules.tar.gz
echo 'b6cb72d07e060fe03e890bb88d40e5c1f2a177780dbb5be1c3b01e5509fd9cec  .build/security-tools/rules.tar.gz' | sha256sum -c -
tar -xzf .build/security-tools/rules.tar.gz --strip-components=1 -C .build/semgrep-rules
