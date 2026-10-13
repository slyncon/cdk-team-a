# cdk-team-a

The claims team's independent Python AWS CDK v2 application for the Partenamut
Developer Enablement case. It consumes a tagged release of the **cdk-launchpad**
package, imports `cdk_launchpad.constructs`, and owns only its stack, handler,
fixtures, tests, and project/CI settings. Shared implementations are not copied.

```text
team S3 bucket → incoming/*.json notification → team Python Lambda → application logs
```

This project deploys **ClaimsTeamStack** to the account selected in the GitHub
`sandbox` environment. The personal account will get a fresh stack. Its app/stack/handler,
construct paths, logical IDs, and outputs are preserved. The synthesizer now uses
dedicated deployment roles, bounded Lambda permissions, and a Claims asset prefix. Stack identity includes its AWS account and region. The corporate sandbox stack
is separate and remains untouched. Review the diff before updating any existing stack.

## Setup and immutable Platform dependency

Team A uses Platform **0.1.1**, pinned to a full Git commit in `requirements.txt`.
`requirements.lock` pins third-party runtime, build, and validation dependencies,
including their distribution hashes. CI actions are pinned to full commits too.
Moving a release tag cannot change this team's installed Platform source.

Prerequisites: Python 3.12, Node 24 LTS/npm, Git. AWS CLI v2 is needed only for
local AWS work; GitHub obtains temporary AWS credentials through OIDC.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps --no-build-isolation -r requirements.txt
python -m pip check
npm ci
export PATH="$PWD/node_modules/.bin:$PATH"
python -m ruff check .
python -m pytest -q
cdk synth
cdk-launchpad-validate .build/cdk.out
python scripts/check_assembly.py .build/cdk.out
```

Local tests and synthesis need no AWS credentials. For a deliberate dependency
update, change the Platform commit and `requirements-deps.in` as needed, then run:

```bash
pip-compile --generate-hashes --allow-unsafe --strip-extras --no-header \
  --no-annotate --output-file requirements.lock requirements-deps.in
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps --no-build-isolation -r requirements.txt
python -m pip check
```

Review the lockfile diff and run all checks before merging. Team B remains on its
selected previous Platform version until it chooses to upgrade. Dependabot opens
updates for tooling; Platform source upgrades remain deliberate.

## Validation and automated deployment

`.github/workflows/ci.yml` has **two separate jobs**:

- **Validate team**: secret scan, hash-locked installation, lint/tests, Python and
  dependency scans, CDK synthesis, and infrastructure policy validation. No AWS access.
- **Deploy Claims sandbox**: runs only after validation, for `main` pushes or a manual
  workflow run on `main`. It uses the saved validated assembly and short-lived OIDC
  credentials, prepares a change set, rejects bucket deletion/replacement, and
  executes safe changes. PRs and scheduled scans never deploy.

Deployment stays disabled until GitHub has a `sandbox` environment allowing only
`main`, and protected `main` requires `Validate team`. A repository variable
`ENABLE_SANDBOX_DEPLOYMENT=true` must also be set after personal-account setup;
it is deliberately unset during preparation. The environment supplies the non-secret
AWS account/region/role variables. The deployment job rechecks assembly hashes and
policy before obtaining AWS credentials. Jobs never bootstrap or destroy stacks.

See [Platform deployment setup](https://github.com/slyncon/partenamut-cdk-use-case/blob/main/DEPLOYMENT.md)
for the exact one-time IAM setup, GitHub settings, credential explanation, and
permission limits. No AWS access keys or SSO tokens should be stored in GitHub.

To run now: **Actions → CI and sandbox deployment → Run workflow → main**.
Expand `Validate team`, followed by `Deploy Claims sandbox`. The summary records
the deployed commit and actual resource outputs. A skipped deployment means the
server-side setup gate is not ready; check its validation-step message.

The shared S3 check rejects missing encryption, public-access flags or TLS denial,
including raw buckets bypassing `SecureBucket`. The Claims check additionally
requires the dedicated CloudFormation role, runtime boundaries on every Lambda
role, supported application resources, and the scoped bootstrap asset prefix.
Tests prove these bypasses fail. Review protection is necessary to stop checks
being removed; CODEOWNERS alone does not enforce reviews.

## Security demonstration and branch protection

```bash
python scripts/security_demo.py secure
cdk-launchpad-validate .build/security-demo

python scripts/security_demo.py insecure
cdk-launchpad-validate .build/security-demo
```

The first gate passes; the second deliberately fails. Correct by rerunning the
`secure` mode and its gate. The script only synthesizes ignored demo files; it
never changes the application's stack or deploys resources. Never deploy
`SecurityDemo`. Negative unit tests pass by asserting that insecure input is rejected.

For an actual failing PR check, temporarily append this step to the workflow on
a demonstration branch:

```yaml
      - name: Demonstrate insecure bucket rejection
        run: |
          python scripts/security_demo.py insecure
          cdk-launchpad-validate .build/security-demo
```

Push/open the PR yourself, observe `Validate team` fail, then change `insecure`
to `secure` and push the correction to show green. Remove the temporary step after
the demonstration. Keep the normal deployed application unchanged.

After the first hosted run, configure `main` protection to require PRs, review,
and the `Validate team` status check with current passing checks. Restrict bypass,
force pushes, and deletion where supported. GitHub Free supports protection and
free standard hosted runners for public repositories; private plan limits differ.
These rules are recommendations, not already configured. See
[protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
and [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

## Manual AWS deployment

Complete the Platform IAM setup above first. Use an authenticated profile for your **personal** AWS account. Account, deployment
region, and OIDC role are GitHub environment variables; no corporate profile or
account is used by Actions. Check sandbox
billing/budget; small fixtures and short application log retention do not guarantee
no charges. All commands below are human-operated. Configure these variables for your personal
account before running commands:

```bash
export PERSONAL_AWS_PROFILE="<your-personal-account-profile>"
export AWS_REGION="<your-deployment-region>"
export AWS_DEFAULT_REGION="$AWS_REGION"
aws sts get-caller-identity --profile "$PERSONAL_AWS_PROFILE"

cdk synth --profile "$PERSONAL_AWS_PROFILE"
cdk-launchpad-validate .build/cdk.out

# Existing sandbox bootstrap is reused; automated jobs never bootstrap.

cdk diff ClaimsTeamStack --profile "$PERSONAL_AWS_PROFILE"
cdk deploy ClaimsTeamStack --profile "$PERSONAL_AWS_PROFILE"
```

Confirm the expected account/region. Review the diff and permission prompt. Stop
if an existing bucket would be replaced/deleted or the diff contains unexpected
changes; do not destroy a deployed stack to migrate directories. Keep stack names,
construct IDs, CDK feature flags, dependency pins, and handler assets stable during
migration. CloudFormation outputs provide actual resource names.

```bash
CLAIMS_BUCKET=$(aws cloudformation describe-stacks --stack-name ClaimsTeamStack \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue | [0]" --output text \
  --profile "$PERSONAL_AWS_PROFILE" --region "$AWS_REGION")
CLAIMS_LOG_GROUP=$(aws cloudformation describe-stacks --stack-name ClaimsTeamStack \
  --query "Stacks[0].Outputs[?OutputKey=='LogGroupName'].OutputValue | [0]" --output text \
  --profile "$PERSONAL_AWS_PROFILE" --region "$AWS_REGION")

aws s3 cp fixtures/claim.json "s3://$CLAIMS_BUCKET/incoming/claim.json" \
  --profile "$PERSONAL_AWS_PROFILE" --region "$AWS_REGION"
aws logs tail "$CLAIMS_LOG_GROUP" --since 10m \
  --profile "$PERSONAL_AWS_PROFILE" --region "$AWS_REGION"
```

Stop if an output is empty or `None`. Notifications are asynchronous; wait briefly
and repeat log reads as needed. The log contains team `claims`, a synthetic document
ID, and `result: processed`. Inputs are fictional JSON metadata, not actual health
or insurance records. Processing means read/validate/log, not claim approval or
payment. The handler never writes S3 objects, and duplicate events are safe to
repeat. Durable retries/dead-letter handling are outside this phase.

## Manual cleanup

No corporate resources are changed by the personal-account deployment. When deliberately
finishing the disposable demo, verify identity and the bucket's actual stack output,
then list its contents before any deletion:

```bash
aws sts get-caller-identity --profile "$PERSONAL_AWS_PROFILE"
aws cloudformation describe-stacks --stack-name ClaimsTeamStack \
  --query 'Stacks[0].Outputs' --output table \
  --profile "$PERSONAL_AWS_PROFILE" --region "$AWS_REGION"
aws s3 ls "s3://$CLAIMS_BUCKET/" --recursive \
  --profile "$PERSONAL_AWS_PROFILE" --region "$AWS_REGION"
```

Only after confirming this is the disposable demo bucket:

```bash
aws s3 rm "s3://$CLAIMS_BUCKET/" --recursive \
  --profile "$PERSONAL_AWS_PROFILE" --region "$AWS_REGION"
cdk destroy ClaimsTeamStack --profile "$PERSONAL_AWS_PROFILE"
```

Empty the bucket before deletion. `DESTROY` is demo-only and automatic object
deletion is disabled; meaningful data would normally merit `RETAIN`. Application
log groups are removed with the stack. Do not destroy shared `CDKToolkit`;
bootstrap assets and notification-helper logs follow the sandbox owner's lifecycle.

OIDC deployment is implemented for this sandbox pilot. Organization-wide policy
enforcement and automatic production deployment remain future work. See the
Platform setup guide for boundaries, branch protections, and limitations.
