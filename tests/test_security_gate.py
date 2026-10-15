"""Policy behavior, scanner evidence contracts and strict demo/release separation."""

import copy
import json
from datetime import date, timedelta

import pytest

from scripts.security_gate import (
    check_coverage,
    cvss_scores,
    demo_inputs,
    evaluate,
    kev_ids,
    main,
    real_inputs,
    trivy_findings,
)

TODAY = date(2026, 10, 15)


@pytest.mark.parametrize(
    "scenario,result,count",
    [
        ("clean", "PASS", 0),
        ("high-cvss", "BLOCK", 1),
        ("kev", "BLOCK", 1),
        ("exception-approved", "ALLOW WITH EXCEPTION", 1),
        ("exception-expired", "BLOCK", 1),
        ("combined-risk", "BLOCK", 2),
    ],
)
def test_manual_scenarios(scenario, result, count):
    findings, kev, exceptions = demo_inputs(scenario)
    decision = evaluate(findings, kev, exceptions, synthetic=True, today=TODAY)
    assert decision["result"] == result
    assert len(decision["findings"]) == count
    assert not decision["release_eligible"]
    assert "SYNTHETIC" in decision["mode"]
    if scenario == "combined-risk":
        assert len(decision["reasons"]) == 2
        assert any("CRITICAL" in reason for reason in decision["reasons"])
        assert any("KEV" in reason for reason in decision["reasons"])


def test_critical_has_actual_cvss_and_version():
    findings, _, _ = demo_inputs("high-cvss")
    assert findings[0]["cvss"] == [{"source": "mock", "version": "3.1", "score": 9.8}]
    assert evaluate(findings, set(), [], today=TODAY)["result"] == "BLOCK"


@pytest.mark.parametrize(
    "change",
    [
        {"component": "other-lib"},
        {"paths": ["other.txt"]},
        {"paths": ["*"]},
        {"approved_by": "Demo developer"},
        {"owner": ""},
        {"statement": ""},
        {"expired_at": "2026-10-15T00:00:00Z"},
        {"expired_at": "2000-01-01T00:00:00Z"},
        {"expired_at": "2099-12-31"},
    ],
)
def test_exception_requires_scope_review_metadata_and_future_expiry(change):
    findings, kev, exceptions = demo_inputs("exception-approved")
    exceptions[0].update(change)
    assert evaluate(findings, kev, exceptions, today=TODAY)["result"] == "BLOCK"


def test_exception_permits_only_authorized_finding_and_preserves_evidence():
    findings, kev, exceptions = demo_inputs("exception-approved")
    original = copy.deepcopy(findings)
    allowed = evaluate(findings, kev, exceptions, today=TODAY)
    assert allowed["release_eligible"]
    assert allowed["findings"][0]["id"] == exceptions[0]["id"]
    other = copy.deepcopy(findings[0])
    other["component"] = "unauthorized-lib"
    assert evaluate(findings + [other], kev, exceptions, today=TODAY)["result"] == "BLOCK"
    assert findings == original


def test_kev_below_high_cannot_be_waived():
    findings, kev, _ = demo_inputs("kev")
    _, _, exceptions = demo_inputs("exception-approved")
    exceptions[0]["id"] = findings[0]["id"]
    decision = evaluate(findings, kev, exceptions, today=TODAY)
    assert findings[0]["severity"] == "MEDIUM"
    assert decision["result"] == "BLOCK"
    assert decision["findings"][0]["exception_status"] == "not permitted for KEV"


def test_scanner_failure_is_not_waivable():
    findings, kev, exceptions = demo_inputs("exception-approved")
    decision = evaluate(findings, kev, exceptions, ["Semgrep failed"], today=TODAY)
    assert decision["result"] == "BLOCK"
    assert not decision["release_eligible"]


def test_missing_evidence_blocks(tmp_path):
    findings, kev, exceptions, failures, _, _ = real_inputs(tmp_path, TODAY)
    assert failures
    assert evaluate(findings, kev, exceptions, failures)["result"] == "BLOCK"


def catalog():
    return {
        "catalogVersion": "2026.10.15",
        "dateReleased": "2026-10-15T00:00:00Z",
        "count": 1,
        "vulnerabilities": [{"cveID": "CVE-2021-44228"}],
    }


def test_cisa_validation_and_real_matching():
    assert kev_ids(catalog(), TODAY) == {"CVE-2021-44228"}


@pytest.mark.parametrize(
    "change",
    [
        {"count": 2},
        {"vulnerabilities": []},
        {"catalogVersion": ""},
        {"dateReleased": "2000-01-01"},
        {"dateReleased": "2099-01-01"},
        {"vulnerabilities": [{"cveID": "made-up"}]},
    ],
)
def test_unavailable_or_invalid_intelligence_fails_closed(change):
    data = catalog()
    data.update(change)
    with pytest.raises((ValueError, KeyError)):
        kev_ids(data, TODAY)


def test_cvss_never_invented_and_numeric_score_can_raise_severity():
    assert cvss_scores({}) == []
    finding = demo_inputs("kev")[0][0]
    finding["cvss"] = cvss_scores({"CVSS": {"nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N"}}})
    assert finding["cvss"][0]["version"] == "3.1"
    assert evaluate([finding], set(), [], today=TODAY)["result"] == "BLOCK"
    with pytest.raises(ValueError):
        cvss_scores({"CVSS": {"nvd": {"V3Score": 99}}})


def test_only_failed_iac_checks_are_findings():
    report = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "stack.json",
                "Misconfigurations": [
                    {"ID": "AWS-0132", "Severity": "HIGH", "Status": "FAIL"},
                    {"ID": "AWS-0067", "Severity": "CRITICAL", "Status": "PASS"},
                ],
            }
        ],
    }
    findings = trivy_findings(report, "misconfiguration")
    assert [f["id"] for f in findings] == ["AWS-0132"]
    assert evaluate(findings, set(), [], today=TODAY)["result"] == "BLOCK"


def test_empty_scans_do_not_satisfy_coverage(tmp_path):
    (tmp_path / "coverage.json").write_text(
        json.dumps(
            {
                "expected_packages": [["requirements.txt", "boto3", "1.0"]],
                "runtime_files": ["index.py"],
                "runtime_packages": 0,
            }
        )
    )
    semgrep = {"version": "1", "paths": {"scanned": ["handler/index.py", "app.py", "stack.py"]}}
    with pytest.raises(ValueError, match="locked"):
        check_coverage(tmp_path, {"dependencies": {"Results": []}}, semgrep)
    with pytest.raises(ValueError, match="Semgrep"):
        check_coverage(tmp_path, {}, {"version": "1", "paths": {"scanned": []}})


def test_default_real_mode_cannot_use_synthetic_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["security_gate.py", "--scenario", "clean"])
    assert main() == 0
    demo = json.loads((tmp_path / ".build/security/synthetic/decision.json").read_text())
    assert not demo["release_eligible"]
    monkeypatch.setattr("sys.argv", ["security_gate.py"])
    assert main() == 1
    real = json.loads((tmp_path / ".build/security/real/decision.json").read_text())
    assert not real["release_eligible"]
    assert real["mode"] == "REAL SCAN"


def test_integrity_failure_blocks_even_clean_demo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SECURITY_PREREQUISITES_OK", "false")
    monkeypatch.setattr("sys.argv", ["security_gate.py", "--scenario", "clean"])
    assert main() == 1


def test_exception_stays_expired_after_presentation_date():
    findings, kev, exceptions = demo_inputs("exception-expired")
    assert (
        evaluate(findings, kev, exceptions, today=TODAY + timedelta(days=365))["result"] == "BLOCK"
    )
