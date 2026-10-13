"""Claims application; its deployment uses dedicated Platform-managed roles."""

import os

from aws_cdk import App, Aws, DefaultStackSynthesizer, Environment
from aws_cdk import aws_iam as iam

from stack import ClaimsTeamStack

app = App()
stack = ClaimsTeamStack(
    app,
    "ClaimsTeamStack",
    env=Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"),
        region=os.getenv("CDK_DEFAULT_REGION"),
    ),
    synthesizer=DefaultStackSynthesizer(
        # Use the current OIDC identity, never assume shared bootstrap admin roles.
        deploy_role_arn="",
        file_asset_publishing_role_arn="",
        lookup_role_arn="",
        bucket_prefix="claims/",
        cloud_formation_execution_role=(
            "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/CDKLaunchpad-TeamA-CloudFormation"
        ),
    ),
)
iam.PermissionsBoundary.of(stack).apply(
    iam.ManagedPolicy.from_managed_policy_arn(
        stack,
        "RuntimeBoundary",
        f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:policy/CDKLaunchpad-TeamA-LambdaBoundary",
    )
)
app.synth()
