"""Validate source/artifact binding and fresh inputs without synthesizing infrastructure."""

import json
import shutil
from pathlib import Path

import pytest

from scripts.security_gate import ROOT
from scripts.security_prepare import prepare


@pytest.fixture
def scan_inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assembly = tmp_path / ".build/cdk.out"
    asset = assembly / "asset.handler"
    asset.mkdir(parents=True)
    (tmp_path / "handler").mkdir()
    for destination in (asset / "index.py", tmp_path / "handler/index.py"):
        shutil.copy2(ROOT / "handler/index.py", destination)
    for name in ("requirements.lock", "requirements.txt", "package.json", "package-lock.json"):
        shutil.copy2(ROOT / name, tmp_path / name)
    function = {
        "Type": "AWS::Lambda::Function",
        "Properties": {"Handler": "index.handler", "Runtime": "python3.12"},
        "Metadata": {"aws:asset:path": "asset.handler"},
    }
    template = assembly / "ClaimsTeamStack.template.json"
    helper = {
        "Type": "AWS::Lambda::Function",
        "Properties": {
            "Handler": "index.handler",
            "Runtime": "python3.13",
            "Code": {"ZipFile": "# helper"},
        },
    }
    template.write_text(
        json.dumps(
            {"Resources": {"ChangedLogicalId": function, "InlineNotificationHelper": helper}}
        )
    )
    return asset, template


def test_prepare_discovers_handler_and_clears_stale_inputs(scan_inputs):
    old_input = Path(".build/security-inputs/stale.txt")
    old_report = Path(".build/security/real/semgrep.json")
    for path in (old_input, old_report):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("stale")
    prepare()
    coverage = json.loads(Path(".build/security/real/coverage.json").read_text())
    assert coverage["runtime_files"] == ["index.py"] and coverage["runtime_packages"] == 0
    assert coverage["expected_packages"]
    assert Path(".build/security-inputs/runtime/index.py").read_bytes() == (
        Path("handler/index.py").read_bytes()
    )
    assert not old_input.exists() and not old_report.exists()


@pytest.mark.parametrize("change", ["tampered-handler", "added-package", "escaped-path"])
def test_unexpected_artifact_fails_preparation(scan_inputs, tmp_path, change):
    asset, template = scan_inputs
    if change == "tampered-handler":
        (asset / "index.py").write_text("# Changed after source checkout\n")
    elif change == "added-package":
        (asset / "METADATA").write_text("Unexpected bundled package")
    else:
        outside = tmp_path / "outside"
        outside.mkdir()
        data = json.loads(template.read_text())
        data["Resources"]["ChangedLogicalId"]["Metadata"]["aws:asset:path"] = str(outside)
        template.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        prepare()
