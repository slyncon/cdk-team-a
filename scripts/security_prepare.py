"""Prepare explicit scan inputs from the already validated assembly; never synthesize/deploy."""

import hashlib
import json
import re
import shutil
from pathlib import Path


def prepare():
    assembly = Path(".build/cdk.out")
    evidence = Path(".build/security/real")
    inputs = Path(".build/security-inputs")
    for path in (evidence, inputs / "dependencies", inputs / "iac", inputs / "runtime"):
        path.mkdir(parents=True, exist_ok=True)
    template = json.loads((assembly / "ClaimsTeamStack.template.json").read_text())
    function = template["Resources"]["ProcessorFunction5B2A90E2"]
    asset = assembly / function["Metadata"]["aws:asset:path"]
    if not asset.is_relative_to(assembly) or not asset.is_dir():
        raise ValueError("Expected CDK staged directory for the Claims Lambda")
    files = sorted(str(p.relative_to(asset)) for p in asset.rglob("*") if p.is_file())
    # This application bundles only its handler. A packaging change must update this contract.
    if (
        files != ["index.py"]
        or (asset / "index.py").read_bytes() != Path("handler/index.py").read_bytes()
    ):
        raise ValueError("Unexpected Lambda inventory or handler differs from validated source")
    shutil.copy2(asset / "index.py", inputs / "runtime/index.py")
    shutil.copy2(
        assembly / "ClaimsTeamStack.template.json", inputs / "iac/ClaimsTeamStack.template.json"
    )
    shutil.copy2("requirements.lock", inputs / "dependencies/requirements.txt")
    for name in ("package.json", "package-lock.json"):
        shutil.copy2(name, inputs / "dependencies" / name)
    expected = [
        ["requirements.txt", name, version]
        for name, version in re.findall(
            r"^([\w.-]+)==([^\s\\]+)", Path("requirements.lock").read_text(), re.MULTILINE
        )
    ]
    npm = json.loads(Path("package-lock.json").read_text())
    expected += [
        ["package-lock.json", path.split("node_modules/")[-1], value["version"]]
        for path, value in npm["packages"].items()
        if path
    ]
    if not expected or not any(item[1] == "boto3" for item in expected):
        raise ValueError("Missing Python SDK dependency inventory")
    coverage = {
        "expected_packages": expected,
        "runtime_files": files,
        "runtime_packages": 0,
        "runtime_asset": str(asset),
        "handler_sha256": hashlib.sha256((asset / "index.py").read_bytes()).hexdigest(),
        "packaging": "CDK directory asset; ZIP created at publishing time, absent from assembly",
        "limitation": "AWS-provided boto3/botocore and Python are absent from this asset",
        "platform_source": Path("requirements.txt").read_text().strip(),
    }
    (evidence / "coverage.json").write_text(json.dumps(coverage, indent=2) + "\n")
    print(json.dumps(coverage, indent=2))


if __name__ == "__main__":
    prepare()
