# Claims team — CDK Launchpad

This independent application consumes Platform's `SecureBucket` and
`DocumentProcessor` from the versioned `cdk-launchpad` package. Team A owns
`ClaimsTeamStack`, its handler, fictional fixture and tests. Shared implementations
are not copied. S3 uploads under `incoming/*.json` invoke a Python Lambda, which
reads/validates the claim and logs a result without writing to S3.

The final interview approach is **automated CI with manual CD**. GitHub validates;
you deploy from WSL using IAM Identity Center profile `cdk-sso`, account
`117301763389`, region `eu-central-1`. No AWS access keys, GitHub AWS secrets, OIDC
role, custom CloudFormation role or external boundary policy is required.

## Local validation

Python 3.12, Node 24 LTS/npm, Make, Git; AWS CLI v2 for manual AWS operations.
From this directory:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
make install
make validate
```

Platform 0.1.2 is installed at the full source commit in requirements.txt, not a
mutable main branch/tag. Its added naming checks do not change existing resource
names. Third-party dependencies and distribution hashes stay in requirements.lock;
CI actions are full commit pins. Platform's dependencies are unchanged for this
upgrade. For deliberate tool/dependency changes, regenerate/review the lock:

```bash
pip-compile --generate-hashes --allow-unsafe --strip-extras --no-header \
  --no-annotate --output-file requirements.lock requirements-deps.in
```

## CI validates and decides release eligibility

On PRs, main pushes, manual workflow runs and scheduled scans, `Build and Validate`
runs secret scanning, lint, tests, Python/dependency audits, synthesis and both
infrastructure validators. It saves the validated assembly/checksums for inspection.
`Security Scan` then checks source with Semgrep and dependencies, the staged Lambda
and synthesized CloudFormation with Trivy, generates SBOMs, and evaluates CISA KEV
and reviewed exceptions. `Release eligible` succeeds only after a genuine approved
scan; it never deploys. All jobs use read-only repository permissions, without AWS
credentials. See [SECURITY_DEMO.md](SECURITY_DEMO.md) for the manual scenario dropdown,
current blocking finding and the interview walkthrough.

There is no deployment job, id-token permission or required GitHub environment.
An old ENABLE_SANDBOX_DEPLOYMENT setting cannot enable a removed job. The earlier
workflow is preserved under `future/oidc-deployment.yml.disabled`, additionally
hard-disabled, and is not ready for restoration. See future/README.md.

Require `Build and Validate`, `Security Scan` and `Release eligible` on main and protected
review of workflows, dependencies, exceptions, stack and policy scripts. CODEOWNERS does not
make reviews mandatory by itself. CI checks do not prevent an administrator from
bypassing review and deploying different code manually.

## Runtime boundary and standard bootstrap

app.py is a normal CDK entry point using the default synthesizer. ClaimsTeamStack
creates its own managed permissions boundary and applies it to every Lambda role,
including CDK's notification helper. The ceiling restricts access to this exact
bucket's incoming objects, bucket metadata/notification setup, and Claims logs.
Application identity policy grants remain read-only. Roles may trust only Lambda.
CI checks policy contents, role references and standard bootstrap deployment/assets.

This replaces the imported boundary ARN, not its security restriction. Standard
CDK bootstrap roles perform deployment; the deleted custom role is not referenced.
The bootstrap CloudFormation role has broader provisioning permissions than the
former scoped role; this is documented sandbox scope, not production isolation.
The runtime boundary does not restrict the human SSO identity or CloudFormation.

Bucket/function construct paths and logical IDs are preserved. In an existing
stack, review the new managed boundary, updated role references and changed asset
keys. Stop on unexpected replacements. No resources were renamed or changed by
preparation of this workflow.

## First manual deployment

Wait for genuine successful GitHub validation and release eligibility (synthetic
green checks do not authorize deployment). Confirm SSO identity, then bootstrap once:

```bash
aws sso login --profile cdk-sso
export AWS_REGION=eu-central-1
export AWS_DEFAULT_REGION=eu-central-1
aws sts get-caller-identity --profile cdk-sso
test "$(aws sts get-caller-identity --profile cdk-sso --query Account --output text)" = "117301763389" || {
  echo "Wrong AWS account; stop before bootstrap or deployment."
  exit 1
}
cdk bootstrap aws://117301763389/eu-central-1 --profile cdk-sso --termination-protection
cdk diff ClaimsTeamStack --profile cdk-sso --change-set false
cdk synth ClaimsTeamStack --profile cdk-sso
cdk-launchpad-validate .build/cdk.out
python scripts/check_assembly.py .build/cdk.out
cdk deploy ClaimsTeamStack --profile cdk-sso
```

Bootstrap is human-operated and required because CDKToolkit does not yet exist in
the target. It creates standard supporting roles/assets; it does not require the
archived IAM/OIDC template. The SSO permission set must authorize bootstrap and
use of its roles. Review the diff/deploy approval. Keep CDKToolkit after the demo.

## Demonstrate a synthetic claim

```bash
CLAIMS_BUCKET=$(aws cloudformation describe-stacks --stack-name ClaimsTeamStack \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue | [0]" --output text \
  --profile cdk-sso --region eu-central-1)
CLAIMS_LOG_GROUP=$(aws cloudformation describe-stacks --stack-name ClaimsTeamStack \
  --query "Stacks[0].Outputs[?OutputKey=='LogGroupName'].OutputValue | [0]" --output text \
  --profile cdk-sso --region eu-central-1)
test -n "$CLAIMS_BUCKET" && test "$CLAIMS_BUCKET" != "None"
test -n "$CLAIMS_LOG_GROUP" && test "$CLAIMS_LOG_GROUP" != "None"
aws s3 cp fixtures/claim.json "s3://$CLAIMS_BUCKET/incoming/claim.json" \
  --profile cdk-sso --region eu-central-1
aws logs tail "$CLAIMS_LOG_GROUP" --since 10m --profile cdk-sso --region eu-central-1
```

Wait briefly for asynchronous delivery if needed. The tiny JSON contains a synthetic
claim ID, category and amount; processing means read/validate/log, not approval or
payment. No real health/insurance information is used. Duplicate events are safe.

For a local policy demonstration, synthesize `scripts/security_demo.py secure`
and run `cdk-launchpad-validate .build/security-demo`; repeat with `insecure` and
observe exit 1. Never deploy SecurityDemo. Negative tests expect rejection.

## Manual cleanup

Verify the account and actual disposable bucket name before deletion. Commands
below are destructive and never run in CI:

```bash
aws sts get-caller-identity --profile cdk-sso
aws s3 ls "s3://$CLAIMS_BUCKET/" --recursive --profile cdk-sso --region eu-central-1
aws s3 rm "s3://$CLAIMS_BUCKET/" --recursive --profile cdk-sso --region eu-central-1
cdk destroy ClaimsTeamStack --profile cdk-sso
```

Empty the identified bucket first. Automatic deletion is disabled; meaningful data
would normally use RETAIN. If versioning is added later, empty versions/delete
markers too. Do not destroy shared CDKToolkit. Check budget/billing; tiny fixtures
and seven-day application logs do not guarantee no charges.

See [Platform deployment guide](https://github.com/slyncon/partenamut-cdk-use-case/blob/main/DEPLOYMENT.md)
for full setup, permission limits and unverified live steps. No cloud operations
were executed while preparing this final approach.
