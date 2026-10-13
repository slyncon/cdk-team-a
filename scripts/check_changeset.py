"""Reject destructive bucket changes before executing a prepared change set."""

import argparse
import os
from pathlib import Path

import boto3


def check_changeset(changeset: dict, account: str, region: str) -> bool:
    expected = f"arn:aws:cloudformation:{region}:{account}:stack/ClaimsTeamStack/"
    if not changeset.get("StackId", "").startswith(expected):
        raise ValueError("Change set must target ClaimsTeamStack in the configured sandbox")
    if changeset["Status"] == "FAILED":
        reason = changeset.get("StatusReason", "")
        if "didn't contain changes" in reason or "No updates are to be performed" in reason:
            return False
        raise ValueError(f"Change set failed: {reason}")
    if changeset["Status"] != "CREATE_COMPLETE":
        raise ValueError("Change set is not ready to execute")
    for change in changeset.get("Changes", []):
        resource = change["ResourceChange"]
        if resource["ResourceType"] == "AWS::S3::Bucket" and (
            resource["Action"] == "Remove" or resource.get("Replacement", "False") != "False"
        ):
            raise ValueError(
                f"Refusing bucket removal/replacement: {resource['LogicalResourceId']}"
            )
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name")
    args = parser.parse_args()
    client = boto3.client("cloudformation")
    pages = client.get_paginator("describe_change_set").paginate(
        StackName="ClaimsTeamStack",
        ChangeSetName=args.name,
    )
    changeset = None
    for page in pages:
        if changeset is None:
            changeset = page
        else:
            changeset.setdefault("Changes", []).extend(page.get("Changes", []))
    execute = check_changeset(changeset, os.environ["AWS_ACCOUNT_ID"], os.environ["AWS_REGION"])
    print("Change set passed bucket safety checks" if execute else "No infrastructure changes")
    if output := os.getenv("GITHUB_OUTPUT"):
        with Path(output).open("a") as stream:
            stream.write(f"execute={str(execute).lower()}\n")
