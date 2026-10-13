"""Claims team's independent CDK application."""

import os

from aws_cdk import App, Environment

from stack import ClaimsTeamStack

app = App()
ClaimsTeamStack(
    app,
    "ClaimsTeamStack",
    env=Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"),
        region=os.getenv("CDK_DEFAULT_REGION"),
    ),
)
app.synth()
