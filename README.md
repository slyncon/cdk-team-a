# cdk-team-a

The claims team's independent Python AWS CDK v2 application for the Partenamut
Developer Enablement case. It consumes a tagged release of the **cdk-launchpad**
package, imports `cdk_launchpad.constructs`, and owns only its stack, handler,
fixtures, tests, and project/CI settings. Shared implementations are not copied.

```text
team S3 bucket → incoming/*.json notification → team Python Lambda → application logs
```

This project targets the **existing deployed ClaimsTeamStack**. Its app/stack/handler,
construct paths, logical IDs, outputs, and CDK settings are preserved. A new local
directory does not create a new stack identity. Review the live diff before using
this checkout to update the existing resources.

## Setup and versioned Platform dependency

Prerequisites: Python 3.12, Node 24 LTS/npm, Git; AWS CLI v2 only for manual AWS work.
Both teams consume the Platform repository at the same tested release:

```text
cdk-launchpad @ git+https://github.com/slyncon/partenamut-cdk-use-case.git@v0.1.0
```

The Python distribution is `cdk-launchpad`; its imports use `cdk_launchpad`.
No package registry, AWS credentials, or GitHub Secrets are needed to install a
public tagged source dependency. The dependency is a regular installation from the Platform release, independent
of sibling directories. Local environments and generated assets are ignored by Git.

From this project's root:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
npm ci
export PATH="$PWD/node_modules/.bin:$PATH"
```

Each repository owns its environment, test/lint settings, and pinned CDK CLI
(`2.1145.0`). The Platform dependency pins the compatible Python CDK library.
To upgrade independently, change this team's ref to a newly published tag such
as `@v0.1.1`, run `python -m pip install --upgrade -r requirements.txt`, then rerun
all checks and the live diff. Other teams keep their chosen version.

## Offline checks and CI

```bash
python -m ruff check .
python -m pytest -q
cdk synth
cdk-launchpad-validate .build/cdk.out
```

These commands require no AWS credentials or resource lookups. The CLI saves the
CloudFormation template and handler assets in `.build/cdk.out/`. A configured
profile may cause read-only account-resolution calls locally. CI sets empty AWS
configuration paths and disables metadata discovery without authenticating to AWS.

`.github/workflows/ci.yml` runs these steps on PRs targeting `main` and pushes to
`main`, using Python 3.12, Node 24, standard Ubuntu runners and `contents: read`.
It installs the pinned tagged Platform dependency and never deploys. Check the repository Actions tab for the hosted result.

Tests mock boto3 reads, reject invalid JSON/fields, verify repeat-safe behavior,
assert platform consumption and notification/resource identities, and exercise
secure/insecure synthesized templates through the installed shared validator.
The validator checks every S3 bucket, including raw buckets bypassing the shared
construct; violations exit 1 with resource-specific messages.

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

Use the existing `partenamut-sso` profile, account **851725255087**, deployment region
**eu-central-1**, and SSO authentication region **eu-west-1**. Check sandbox
billing/budget; small fixtures and short application log retention do not guarantee
no charges. All commands below are human-operated. Refresh SSO if needed:

```bash
aws sso login --profile partenamut-sso
aws sts get-caller-identity --profile partenamut-sso
export AWS_REGION=eu-central-1
export AWS_DEFAULT_REGION=eu-central-1

cdk synth --profile partenamut-sso
cdk-launchpad-validate .build/cdk.out

# Only if this account/region needs CDK bootstrap resources; skip if already ready.
cdk bootstrap --profile partenamut-sso

cdk diff ClaimsTeamStack --profile partenamut-sso
cdk deploy ClaimsTeamStack --profile partenamut-sso
```

Confirm the expected account/region. Review the diff and permission prompt. Stop
if an existing bucket would be replaced/deleted or the diff contains unexpected
changes; do not destroy a deployed stack to migrate directories. Keep stack names,
construct IDs, CDK feature flags, dependency pins, and handler assets stable during
migration. CloudFormation outputs provide actual resource names.

```bash
CLAIMS_BUCKET=$(aws cloudformation describe-stacks --stack-name ClaimsTeamStack \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue | [0]" --output text \
  --profile partenamut-sso --region eu-central-1)
CLAIMS_LOG_GROUP=$(aws cloudformation describe-stacks --stack-name ClaimsTeamStack \
  --query "Stacks[0].Outputs[?OutputKey=='LogGroupName'].OutputValue | [0]" --output text \
  --profile partenamut-sso --region eu-central-1)

aws s3 cp fixtures/claim.json "s3://$CLAIMS_BUCKET/incoming/claim.json" \
  --profile partenamut-sso --region eu-central-1
aws logs tail "$CLAIMS_LOG_GROUP" --since 10m \
  --profile partenamut-sso --region eu-central-1
```

Stop if an output is empty or `None`. Notifications are asynchronous; wait briefly
and repeat log reads as needed. The log contains team `claims`, a synthetic document
ID, and `result: processed`. Inputs are fictional JSON metadata, not actual health
or insurance records. Processing means read/validate/log, not claim approval or
payment. The handler never writes S3 objects, and duplicate events are safe to
repeat. Durable retries/dead-letter handling are outside this phase.

## Manual cleanup

Migration does not require cleanup of the existing stack. When deliberately
finishing the disposable demo, verify identity and the bucket's actual stack output,
then list its contents before any deletion:

```bash
aws sts get-caller-identity --profile partenamut-sso
aws cloudformation describe-stacks --stack-name ClaimsTeamStack \
  --query 'Stacks[0].Outputs' --output table \
  --profile partenamut-sso --region eu-central-1
aws s3 ls "s3://$CLAIMS_BUCKET/" --recursive \
  --profile partenamut-sso --region eu-central-1
```

Only after confirming this is the disposable demo bucket:

```bash
aws s3 rm "s3://$CLAIMS_BUCKET/" --recursive \
  --profile partenamut-sso --region eu-central-1
cdk destroy ClaimsTeamStack --profile partenamut-sso
```

Empty the bucket before deletion. `DESTROY` is demo-only and automatic object
deletion is disabled; meaningful data would normally merit `RETAIN`. Application
log groups are removed with the stack. Do not destroy shared `CDKToolkit`;
bootstrap assets and notification-helper logs follow the sandbox owner's lifecycle.

Future automated deployment could use separate protected GitHub Actions workflows
and GitHub OIDC with narrowly scoped AWS roles and approvals. No OIDC, AWS keys,
Secrets, or deployment automation are implemented in this phase.
