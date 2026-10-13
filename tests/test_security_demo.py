import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("mode,expected_exit", [("secure", 0), ("insecure", 1)])
def test_synthesized_security_demonstration(tmp_path, mode, expected_exit):
    script = Path(__file__).resolve().parents[1] / "scripts/security_demo.py"
    synth = subprocess.run(
        [sys.executable, str(script), mode],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert synth.returncode == 0, synth.stderr
    result = subprocess.run(
        [sys.executable, "-m", "cdk_launchpad.cli", ".build/security-demo"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == expected_exit
    if expected_exit:
        assert "BucketEncryption" in result.stderr
        assert "BlockPublicPolicy" in result.stderr
    else:
        assert "Security validation passed" in result.stdout
