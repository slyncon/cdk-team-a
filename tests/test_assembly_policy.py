import json
from pathlib import Path

import pytest
import yaml
from aws_cdk import App, Aws, DefaultStackSynthesizer
from aws_cdk import aws_iam as iam

from scripts.check_assembly import check_assembly
from stack import ClaimsTeamStack


@pytest.fixture
def assembly(tmp_path):
    app = App(outdir=str(tmp_path / "assembly"))
    stack = ClaimsTeamStack(
        app,
        "ClaimsTeamStack",
        synthesizer=DefaultStackSynthesizer(
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
            "Boundary",
            f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:policy/CDKLaunchpad-TeamA-LambdaBoundary",
        )
    )
    app.synth()
    return tmp_path / "assembly"


def test_current_assembly_passes(assembly):
    check_assembly(assembly)


@pytest.mark.parametrize(
    "bypass", ["missing-boundary", "other-service", "bootstrap-role", "foreign-trust"]
)
def test_deployment_policy_bypasses_fail(assembly, bypass):
    path = assembly / "ClaimsTeamStack.template.json"
    template = json.loads(path.read_text())
    if bypass == "missing-boundary":
        role = next(r for r in template["Resources"].values() if r["Type"] == "AWS::IAM::Role")
        del role["Properties"]["PermissionsBoundary"]
        path.write_text(json.dumps(template))
    elif bypass == "foreign-trust":
        role = next(r for r in template["Resources"].values() if r["Type"] == "AWS::IAM::Role")
        role["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] = {"AWS": "*"}
        path.write_text(json.dumps(template))
    elif bypass == "other-service":
        template["Resources"]["Unexpected"] = {"Type": "AWS::SQS::Queue"}
        path.write_text(json.dumps(template))
    else:
        manifest_path = assembly / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["artifacts"]["ClaimsTeamStack"]["properties"]["assumeRoleArn"] = "admin"
        manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        check_assembly(assembly)


def test_deployment_job_requires_validation_and_has_exclusive_oidc_access():
    path = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    workflow = yaml.safe_load(path.read_text())
    jobs = workflow["jobs"]
    assert jobs["deploy"]["needs"] == "validate"
    assert jobs["deploy"]["environment"] == "sandbox"
    assert "refs/heads/main" in jobs["deploy"]["if"]
    assert "vars.ENABLE_SANDBOX_DEPLOYMENT" in jobs["deploy"]["if"]
    assert jobs["deploy"]["permissions"]["id-token"] == "write"
    assert "permissions" not in jobs["validate"]
    assert workflow["permissions"] == {"contents": "read"}
    assert jobs["deploy"]["concurrency"]["cancel-in-progress"] is False
    for job in jobs.values():
        for step in job["steps"]:
            if action := step.get("uses"):
                assert len(action.rsplit("@", 1)[1]) == 40
    deploy_commands = "\n".join(s.get("run", "") for s in jobs["deploy"]["steps"])
    assert "--app .build/cdk.out" in deploy_commands
    assert "cdk synth" not in deploy_commands
    assert "scripts/check_changeset.py" in deploy_commands
