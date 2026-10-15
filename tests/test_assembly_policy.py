import json
from pathlib import Path

import pytest
import yaml
from aws_cdk import App, Environment

from scripts.check_assembly import check_assembly
from stack import ClaimsTeamStack


@pytest.fixture(params=[False, True])
def assembly(tmp_path, request):
    app = App(outdir=str(tmp_path / "assembly"))
    kwargs = {}
    if request.param:
        kwargs["env"] = Environment(account="000000000000", region="eu-central-1")
    ClaimsTeamStack(app, "ClaimsTeamStack", **kwargs)
    app.synth()
    return tmp_path / "assembly"


def test_standard_bootstrap_and_owned_boundary_pass(assembly):
    check_assembly(assembly)


@pytest.mark.parametrize(
    "bypass",
    [
        "missing-boundary",
        "external-boundary",
        "other-service",
        "custom-execution-role",
        "foreign-trust",
        "broad-boundary",
        "write-boundary",
        "custom-publishing-role",
        "forbidden-name",
        "forbidden-tag",
    ],
)
def test_security_bypasses_and_missing_external_dependencies_fail(assembly, bypass):
    path = assembly / "ClaimsTeamStack.template.json"
    template = json.loads(path.read_text())
    role = next(r for r in template["Resources"].values() if r["Type"] == "AWS::IAM::Role")
    policy = next(
        r for r in template["Resources"].values() if r["Type"] == "AWS::IAM::ManagedPolicy"
    )
    if bypass == "missing-boundary":
        del role["Properties"]["PermissionsBoundary"]
    elif bypass == "external-boundary":
        role["Properties"]["PermissionsBoundary"] = "arn:aws:iam::000000000000:policy/deleted"
    elif bypass == "foreign-trust":
        role["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] = {"AWS": "*"}
    elif bypass == "other-service":
        template["Resources"]["Unexpected"] = {"Type": "AWS::SQS::Queue"}
    elif bypass == "broad-boundary":
        policy["Properties"]["PolicyDocument"]["Statement"][0]["Resource"] = "*"
    elif bypass == "write-boundary":
        policy["Properties"]["PolicyDocument"]["Statement"][1]["Action"] = "s3:PutObject"
    elif bypass == "forbidden-name":
        role["Properties"]["RoleName"] = "partenamut-reader"
    elif bypass == "forbidden-tag":
        role["Properties"]["Tags"] = [{"Key": "Project", "Value": "partenamut"}]
    elif bypass == "custom-execution-role":
        manifest_path = assembly / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["artifacts"]["ClaimsTeamStack"]["properties"]["cloudFormationExecutionRoleArn"] = (
            "arn:aws:iam::000000000000:role/deleted-custom-role"
        )
        manifest_path.write_text(json.dumps(manifest))
    else:
        manifest = json.loads((assembly / "manifest.json").read_text())
        assets_path = (
            assembly / manifest["artifacts"]["ClaimsTeamStack.assets"]["properties"]["file"]
        )
        assets = json.loads(assets_path.read_text())
        for asset in assets["files"].values():
            for destination in asset["destinations"].values():
                destination["assumeRoleArn"] = "arn:aws:iam::000000000000:role/deleted-publisher"
        assets_path.write_text(json.dumps(assets))
    path.write_text(json.dumps(template))
    with pytest.raises(ValueError):
        check_assembly(assembly)


def test_boundary_has_no_cloudformation_dependency_cycle(assembly):
    resources = json.loads((assembly / "ClaimsTeamStack.template.json").read_text())["Resources"]

    def references(value):
        found = set()
        if isinstance(value, dict):
            if "Ref" in value and value["Ref"] in resources:
                found.add(value["Ref"])
            if "Fn::GetAtt" in value:
                target = value["Fn::GetAtt"][0]
                if target in resources:
                    found.add(target)
            for child in value.values():
                found.update(references(child))
        elif isinstance(value, list):
            for child in value:
                found.update(references(child))
        return found

    graph = {}
    for name, resource in resources.items():
        dependencies = resource.get("DependsOn", [])
        if isinstance(dependencies, str):
            dependencies = [dependencies]
        graph[name] = references(resource) | set(dependencies)

    def visit(name, ancestors):
        assert name not in ancestors, f"Resource dependency cycle: {ancestors} → {name}"
        for dependency in graph.get(name, []):
            visit(dependency, ancestors | {name})

    for name in graph:
        visit(name, set())


def test_active_ci_has_no_aws_deployment_or_oidc_permissions():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    assert set(workflow["jobs"]) == {"validate", "security", "release-eligible"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["validate"]
    assert "permissions" not in job and "environment" not in job
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    for forbidden in ["cdk deploy", "cdk bootstrap", "cdk destroy", "check_github_environment"]:
        assert forbidden not in commands
    for expected in [
        "pytest",
        "ruff",
        "bandit",
        "pip_audit",
        "npm audit",
        "cdk synth",
        "cdk-launchpad-validate",
        "check_assembly",
    ]:
        assert expected in commands
    for active_job in workflow["jobs"].values():
        assert "permissions" not in active_job and "environment" not in active_job
        for step in active_job["steps"]:
            if action := step.get("uses"):
                assert len(action.rsplit("@", 1)[1]) == 40
                assert "configure-aws-credentials" not in action
            for forbidden in ["cdk deploy", "cdk bootstrap", "cdk destroy"]:
                assert forbidden not in step.get("run", "")
    security = workflow["jobs"]["security"]
    assert security["name"] == "Security Scan" and security["needs"] == "validate"
    release = workflow["jobs"]["release-eligible"]
    assert "release_eligible == 'true'" in release["steps"][0]["env"]["APPROVED"]
    assert "inputs.scenario == 'real'" in release["if"] and "always()" in release["if"]
    assert "SYNTHETIC - no release approval" in release["name"]
    assert "exit 1" in release["steps"][0]["run"]
    # PyYAML's YAML 1.1 parser reads GitHub's unquoted 'on' key as True.
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"push", "pull_request", "workflow_dispatch", "schedule"}
    assert triggers["workflow_dispatch"]["inputs"]["scenario"]["default"] == "real"
    archive = yaml.safe_load((root / "future/oidc-deployment.yml.disabled").read_text())
    assert archive["jobs"]["deploy"]["if"].startswith("${{ false }}")
    assert not list((root / ".github/workflows").glob("*deploy*"))
