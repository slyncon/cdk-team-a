"""Check Claims runtime security and standard bootstrap metadata for manual CD."""

import argparse
import json
import re
from pathlib import Path

from cdk_launchpad.security import validate_template

ALLOWED_TYPES = {
    "AWS::S3::Bucket",
    "AWS::S3::BucketPolicy",
    "AWS::Lambda::Function",
    "AWS::Lambda::Permission",
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::Logs::LogGroup",
    "Custom::S3BucketNotifications",
    "AWS::CDK::Metadata",
}


def resolve(value, account, region):
    replacements = {"AWS::Partition": "aws", "AWS::AccountId": account, "AWS::Region": region}
    if isinstance(value, str):
        for key, replacement in replacements.items():
            value = value.replace("${" + key + "}", replacement)
        return value
    if isinstance(value, list):
        return [resolve(child, account, region) for child in value]
    if isinstance(value, dict):
        if value.get("Ref") in replacements:
            return replacements[value["Ref"]]
        if "Fn::Join" in value:
            separator, parts = value["Fn::Join"]
            parts = resolve(parts, account, region)
            if all(isinstance(part, str) for part in parts):
                return separator.join(parts)
            return {"Fn::Join": [separator, parts]}
        return {key: resolve(child, account, region) for key, child in value.items()}
    return value


def canonical(statement):
    result = dict(statement)
    result.pop("Sid", None)
    for key in ("Action", "Resource"):
        values = result.get(key, [])
        if not isinstance(values, list):
            values = [values]
        result[key] = sorted(values, key=lambda value: json.dumps(value, sort_keys=True))
    return json.dumps(result, sort_keys=True)


def check_runtime_boundary(template, account, region):
    resources = template["Resources"]
    policies = {
        key: value for key, value in resources.items() if value["Type"] == "AWS::IAM::ManagedPolicy"
    }
    buckets = [key for key, value in resources.items() if value["Type"] == "AWS::S3::Bucket"]
    logs = [key for key, value in resources.items() if value["Type"] == "AWS::Logs::LogGroup"]
    if len(policies) != 1 or len(buckets) != 1 or len(logs) != 1:
        raise ValueError(
            "Claims requires one owned bucket, application log group and runtime boundary"
        )
    policy_id, policy = next(iter(policies.items()))
    bucket_arn = {"Fn::GetAtt": [buckets[0], "Arn"]}
    expected = [
        {
            "Effect": "Allow",
            "Action": ["s3:GetBucket*", "s3:ListBucket", "s3:PutBucketNotification"],
            "Resource": bucket_arn,
        },
        {
            "Effect": "Allow",
            "Action": "s3:GetObject*",
            "Resource": {"Fn::Join": ["", [bucket_arn, "/incoming/*"]]},
        },
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": [
                {"Fn::GetAtt": [logs[0], "Arn"]},
                f"arn:aws:logs:{region}:{account}:log-group:/aws/lambda/ClaimsTeamStack-*",
            ],
        },
    ]
    document = resolve(policy["Properties"]["PolicyDocument"], account, region)
    if document.get("Version") != "2012-10-17" or sorted(
        canonical(s) for s in document.get("Statement", [])
    ) != sorted(canonical(s) for s in expected):
        raise ValueError(
            "Runtime boundary must limit access to Claims reads, notification setup and logs"
        )
    for key, resource in resources.items():
        if resource["Type"] != "AWS::IAM::Role":
            continue
        if resource["Properties"].get("PermissionsBoundary") != {"Ref": policy_id}:
            raise ValueError(f"{key}: required stack-owned runtime boundary is missing")
        trust = resource["Properties"].get("AssumeRolePolicyDocument", {}).get("Statement", [])
        if not trust or any(
            s.get("Effect") != "Allow"
            or s.get("Principal") != {"Service": "lambda.amazonaws.com"}
            or s.get("Action") not in ("sts:AssumeRole", ["sts:AssumeRole"])
            for s in trust
        ):
            raise ValueError(f"{key}: runtime roles may trust only Lambda")


def bootstrap_role(kind, account, region):
    return f"arn:aws:iam::{account}:role/cdk-hnb659fds-{kind}-{account}-{region}"


def check_assembly(directory: Path) -> None:
    manifest = json.loads((directory / "manifest.json").read_text())
    stacks = {
        key: value
        for key, value in manifest["artifacts"].items()
        if value["type"] == "aws:cloudformation:stack"
    }
    if set(stacks) != {"ClaimsTeamStack"}:
        raise ValueError("Only ClaimsTeamStack may be deployed")
    stack = stacks["ClaimsTeamStack"]
    account, region = stack["environment"].removeprefix("aws://").split("/")
    account = "${AWS::AccountId}" if account == "unknown-account" else account
    region = "${AWS::Region}" if region == "unknown-region" else region
    properties = stack["properties"]
    template = json.loads((directory / properties["templateFile"]).read_text())
    errors = validate_template(template)
    if errors:
        raise ValueError("; ".join(errors))
    for key, resource in template["Resources"].items():
        if resource["Type"] not in ALLOWED_TYPES:
            raise ValueError(f"{key}: unsupported resource type {resource['Type']}")
    check_runtime_boundary(template, account, region)
    expected_roles = {
        "assumeRoleArn": bootstrap_role("deploy-role", account, region),
        "cloudFormationExecutionRoleArn": bootstrap_role("cfn-exec-role", account, region),
    }
    for key, expected in expected_roles.items():
        if resolve(properties.get(key), account, region) != expected:
            raise ValueError("Manual deployment requires the standard CDK bootstrap roles")
    for artifact in manifest["artifacts"].values():
        if artifact["type"] != "cdk:asset-manifest":
            continue
        assets = json.loads((directory / artifact["properties"]["file"]).read_text())
        if assets.get("dockerImages"):
            raise ValueError("Docker assets are outside this demo")
        for asset in assets.get("files", {}).values():
            for raw_destination in asset["destinations"].values():
                destination = resolve(raw_destination, account, region)
                if (
                    destination.get("assumeRoleArn")
                    != bootstrap_role("file-publishing-role", account, region)
                    or destination["bucketName"] != f"cdk-hnb659fds-assets-{account}-{region}"
                    or not re.fullmatch(r"[0-9a-f]{64}\.(zip|json)", destination["objectKey"])
                ):
                    raise ValueError("Assets must use standard bootstrap publishing")
    print("Claims manual-deployment security policy passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    check_assembly(parser.parse_args().directory)
