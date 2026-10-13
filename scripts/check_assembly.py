"""Enforce the supported Claims deployment shape, including all runtime boundaries."""

import argparse
import json
from pathlib import Path

BOUNDARY = {
    "Fn::Join": [
        "",
        [
            "arn:",
            {"Ref": "AWS::Partition"},
            ":iam::",
            {"Ref": "AWS::AccountId"},
            ":policy/CDKLaunchpad-TeamA-LambdaBoundary",
        ],
    ]
}
ALLOWED_TYPES = {
    "AWS::S3::Bucket",
    "AWS::S3::BucketPolicy",
    "AWS::Lambda::Function",
    "AWS::Lambda::Permission",
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::Logs::LogGroup",
    "Custom::S3BucketNotifications",
    "AWS::CDK::Metadata",
}


def check_assembly(directory: Path) -> None:
    manifest = json.loads((directory / "manifest.json").read_text())
    stacks = {
        key: value
        for key, value in manifest["artifacts"].items()
        if value["type"] == "aws:cloudformation:stack"
    }
    if set(stacks) != {"ClaimsTeamStack"}:
        raise ValueError("Only the ClaimsTeamStack application may be deployed")
    stack = stacks["ClaimsTeamStack"]
    template = json.loads((directory / stack["properties"]["templateFile"]).read_text())
    for key, resource in template["Resources"].items():
        if resource["Type"] not in ALLOWED_TYPES:
            raise ValueError(f"{key}: unsupported resource type {resource['Type']}")
        if resource["Type"] == "AWS::IAM::Role":
            if resource["Properties"].get("PermissionsBoundary") != BOUNDARY:
                raise ValueError(f"{key}: required Claims runtime permissions boundary is missing")
            trust = resource["Properties"].get("AssumeRolePolicyDocument", {}).get("Statement", [])
            if not trust or any(
                statement.get("Effect") != "Allow"
                or statement.get("Principal") != {"Service": "lambda.amazonaws.com"}
                or statement.get("Action") not in ("sts:AssumeRole", ["sts:AssumeRole"])
                for statement in trust
            ):
                raise ValueError(f"{key}: runtime roles may trust only the Lambda service")
    properties = stack["properties"]
    if properties.get("assumeRoleArn"):
        raise ValueError("Deployment must not assume shared bootstrap roles")
    expected = "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/CDKLaunchpad-TeamA-CloudFormation"
    if properties.get("cloudFormationExecutionRoleArn") != expected:
        raise ValueError("The dedicated Claims CloudFormation execution role is required")
    for artifact in manifest["artifacts"].values():
        if artifact["type"] != "cdk:asset-manifest":
            continue
        assets = json.loads((directory / artifact["properties"]["file"]).read_text())
        if assets.get("dockerImages"):
            raise ValueError("Docker assets are outside this deployment's permissions")
        for asset in assets.get("files", {}).values():
            for destination in asset["destinations"].values():
                if destination.get("assumeRoleArn") or not destination["objectKey"].startswith(
                    "claims/"
                ):
                    raise ValueError("Assets must use the current identity and Claims asset prefix")
    print("Claims deployment policy passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    check_assembly(parser.parse_args().directory)
