"""Evaluate scanner evidence or a synthetic scenario and publish one security report."""

import argparse
import json
import os
import re
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ("real", "clean", "high-cvss", "kev", "exception-approved",
             "exception-expired", "combined-risk")
MANDATORY = ("semgrep", "dependencies", "iac", "runtime", "dependencies-sbom", "runtime-sbom",
             "dependencies-readable", "iac-readable", "runtime-readable", "kev")


def load(path):
    return json.loads(Path(path).read_text())


def kev_ids(catalog, today):
    entries = catalog["vulnerabilities"]
    released = date.fromisoformat(catalog["dateReleased"][:10])
    if (not catalog["catalogVersion"] or not entries or catalog["count"] != len(entries)
            or not today - timedelta(days=30) <= released <= today):
        raise ValueError("CISA catalog is empty, inconsistent, stale or future-dated")
    ids = {entry["cveID"] for entry in entries}
    if not all(re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) for cve in ids):
        raise ValueError("Invalid CVE identifier in CISA catalog")
    return ids


def cvss_scores(item):
    scores = []
    for source, values in item.get("CVSS", {}).items():
        for field, version in (("V2Score", "2.0"), ("V3Score", "3.x"), ("V40Score", "4.0")):
            if field not in values:
                continue
            score = values[field]
            if type(score) not in (float, int) or not 0 <= score <= 10:
                raise ValueError("Invalid numeric CVSS score")
            vector = values.get(field.replace("Score", "Vector"), "")
            if vector.startswith("CVSS:"):
                version = vector.split("/")[0].removeprefix("CVSS:")
            scores.append({"source": source, "version": version, "score": score})
    return scores


def trivy_findings(report, kind):
    if report.get("SchemaVersion") != 2:
        raise ValueError("Unsupported or missing Trivy schema")
    findings = []
    for result in report.get("Results", []):
        for item in result.get("Vulnerabilities", []) + result.get("Misconfigurations", []):
            if kind == "misconfiguration" and item.get("Status") != "FAIL":
                continue
            severity = item["Severity"].upper()
            if severity not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ValueError("Unknown severity value")
            component = item.get("PkgName") or item.get("CauseMetadata", {}).get("Resource")
            findings.append({
                "id": item.get("VulnerabilityID") or item["ID"], "kind": kind,
                "severity": severity, "component": component or item.get("Type", "IaC"),
                "scope": result["Target"], "cvss": cvss_scores(item),
                "version": item.get("InstalledVersion", ""), "fix": item.get("FixedVersion", ""),
            })
    return findings


def exception_status(finding, exceptions, today):
    candidates = [e for e in exceptions if e.get("id") == finding["id"]]
    scoped = [e for e in candidates if e.get("paths") == [finding["scope"]]
              and e.get("component") == finding["component"]]
    if not candidates:
        return "none", {}
    if not scoped:
        return "scope mismatch", candidates[0]
    for item in scoped:
        required = ("statement", "owner", "approved_by", "expired_at")
        if not all(isinstance(item.get(k), str) and item[k].strip() for k in required):
            status = "invalid metadata"
        elif item["owner"].strip().casefold() == item["approved_by"].strip().casefold():
            status = "requires independent approver"
        elif not re.fullmatch(r"\d{4}-\d{2}-\d{2}T00:00:00Z", item["expired_at"]):
            status = "invalid expiry (use UTC midnight timestamp)"
        elif date.fromisoformat(item["expired_at"][:10]) <= today:
            status = "expired"
        else:
            return "valid", item
    return status, scoped[0]


def evaluate(findings, kev, exceptions, failures=(), *, synthetic=False, today=None):
    reasons, reviewed = list(failures), []
    for finding in findings:
        item = dict(finding, kev=finding["id"] in kev)
        status, exception = exception_status(item, exceptions, today or date.today())
        if item["kev"]:
            reason = "mock KEV match" if synthetic else "CISA KEV match"
            reasons.append(f"{item['id']}: {reason} cannot be waived")
            status = "not permitted for KEV"
        elif item["kind"] == "sast":
            reasons.append(f"{item['id']}: configured Semgrep security rule")
            status = "not permitted for SAST"
        elif (item["severity"] in {"HIGH", "CRITICAL"}
              or any(s["score"] >= 7 for s in item["cvss"])) and status != "valid":
            reasons.append(f"{item['id']}: {item['severity']} / CVSS policy; exception {status}")
        reviewed.append(dict(item, exception_status=status, exception=exception))
    allowed_exception = any(f["exception_status"] == "valid" for f in reviewed)
    result = "BLOCK" if reasons else "ALLOW WITH EXCEPTION" if allowed_exception else "PASS"
    return {"mode": "synthetic" if synthetic else "real", "result": result,
            "reasons": reasons, "findings": reviewed,
            "release_eligible": not synthetic and result != "BLOCK"}


def check_coverage(evidence, reports, semgrep):
    coverage = load(evidence / "coverage.json")
    if not {"handler/index.py", "app.py", "stack.py"} <= set(semgrep["paths"]["scanned"]):
        raise ValueError("Semgrep skipped required Python source")
    if not semgrep.get("version"):
        raise ValueError("Missing Semgrep version")
    packages = {(r["Target"], p["Name"], p["Version"])
                for r in reports["dependencies"].get("Results", []) for p in r.get("Packages", [])}
    expected = set(map(tuple, coverage["expected_packages"]))
    if not expected or not expected <= packages:
        raise ValueError("Trivy skipped locked Python/npm dependencies")
    checks = [r.get("MisconfSummary", {}) for r in reports["iac"].get("Results", [])
              if r["Type"] == "cloudformation" and r["Target"] == "ClaimsTeamStack.template.json"]
    if not any(c.get("Successes", 0) + c.get("Failures", 0) for c in checks):
        raise ValueError("Trivy did not evaluate synthesized CloudFormation checks")
    if coverage["runtime_files"] != ["index.py"] or coverage["runtime_packages"] != 0:
        raise ValueError("Lambda packaging changed: update the runtime coverage contract")
    if any(r.get("Packages") for r in reports["runtime"].get("Results", [])):
        raise ValueError("Unexpected packaged runtime dependencies")
    for name in ("dependencies", "runtime"):
        sbom = load(evidence / f"{name}.cdx.json")
        if sbom.get("bomFormat") != "CycloneDX":
            raise ValueError(f"Missing CycloneDX {name} SBOM")
        if name == "dependencies" and not sbom.get("components"):
            raise ValueError("Empty dependency SBOM")
    return coverage


def real_inputs(evidence, today):
    findings, failures, statuses, coverage = [], [], {}, {}
    try:
        lines = (evidence / "status.tsv").read_text().splitlines()
        statuses = dict(line.split("\t") for line in lines)
        failures += [f"Mandatory scanner/evidence failure: {k} (exit {statuses.get(k, 'missing')})"
                     for k in MANDATORY if statuses.get(k) != "0"]
    except (OSError, ValueError) as error:
        failures.append(f"Missing scanner completion evidence: {error}")
    kev, exceptions = set(), []
    try:
        semgrep = load(evidence / "semgrep.json")
        if semgrep["errors"]:
            failures.append("Semgrep reported scan errors")
        for item in semgrep["results"]:
            levels = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
            severity = levels[item["extra"]["severity"]]
            findings.append({"id": item["check_id"], "kind": "sast", "scope": item["path"],
                             "component": "Python source", "severity": severity, "cvss": []})
        reports = {k: load(evidence / f"{k}.json") for k in ("dependencies", "iac", "runtime")}
        for name, report in reports.items():
            kind = "misconfiguration" if name == "iac" else "dependency"
            findings.extend(trivy_findings(report, kind))
        coverage = check_coverage(evidence, reports, semgrep)
        kev = kev_ids(load(evidence / "kev.json"), today)
        config = load(ROOT / "security/trivyignore.yaml")  # JSON is valid native YAML.
        exceptions = config["vulnerabilities"] + config["misconfigurations"]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        failures.append(f"Missing or invalid required evidence: {error}")
    return findings, kev, exceptions, failures, statuses, coverage


def demo_inputs(scenario):
    fixture = load(ROOT / "security/scenarios.json")
    findings = [dict(fixture["findings"][key]) for key in fixture["scenarios"][scenario]]
    exceptions = [dict(fixture["exception"])] if scenario.startswith("exception-") else []
    if scenario == "exception-expired":
        exceptions[0]["expired_at"] = "2000-01-01T00:00:00Z"
    return findings, set(fixture["mock_kev"]), exceptions


def markdown(decision, statuses, coverage, scenario="real"):
    synthetic = decision["mode"] == "synthetic"
    counts = Counter(f["severity"] for f in decision["findings"])
    lines = [f"## Security Scan: {scenario}", f"**Result: {decision['result']}**", "",
             f"Mode: {decision['mode']} · Release eligible: "
             + ("Yes" if decision["release_eligible"] else "No"), ""]
    if synthetic:
        lines += ["Synthetic input with a mock KEV catalog. Real scanners are skipped.", ""]
    else:
        lines += ["| Check | Status |", "|---|---|"]
        for label, key in (("Semgrep", "semgrep"), ("Trivy dependencies", "dependencies"),
                           ("Trivy infrastructure", "iac"), ("Trivy Lambda artifact", "runtime")):
            status = "Completed" if statuses.get(key) == "0" else "Failed / missing evidence"
            lines.append(f"| {label} | {status} |")
    lines += ["", " · ".join(f"{k.title()}: {counts[k]}" for k in
              ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")), "",
              "| ID | Severity | Component / scope | CVSS (source, version) | KEV | "
              "Exception (status / owner / approver / expiry) |",
              "|---|---|---|---|---|---|"]
    for f in decision["findings"]:
        scores = "; ".join(f"{s['score']} ({s['source']}, v{s['version']})" for s in f["cvss"])
        e = f["exception"]
        exception = " / ".join([f["exception_status"]] +
                               [e[k] for k in ("owner", "approved_by", "expired_at") if k in e])
        kev = ("Yes (mock)" if synthetic else "Yes") if f["kev"] else "No"
        cells = [f["id"], f["severity"], f"{f['component']} / {f['scope']}",
                 scores or "Not provided", kev, exception]
        cells = [str(c).replace("|", "\\|").replace("\n", " ").replace("\r", " ") for c in cells]
        lines.append("| " + " | ".join(cells) + " |")
    reasons = decision["reasons"] or ["No blocking findings."]
    lines += ["", "**Reasons:**"] + [f"- {r}" for r in reasons]
    if coverage:
        lines += ["", f"Coverage: {len(coverage['expected_packages'])} locked packages, "
                  "CloudFormation and the verified handler. No bundled runtime packages; "
                  "AWS-provided SDK versions are outside this inventory."]
    action = "Run real to assess this commit." if synthetic else (
        "Review reports/SBOMs, fix findings or failed scanners, and rerun. "
        "Request a reviewed, scoped exception only if justified.")
    return "\n".join(lines + ["", "**Next action:** " + action, ""])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, default="real")
    parser.add_argument("--evidence", type=Path, default=Path(".build/security/real"))
    args = parser.parse_args()
    synthetic = args.scenario != "real"
    statuses, coverage, failures = {}, {}, []
    if synthetic:
        findings, kev, exceptions = demo_inputs(args.scenario)
        output = Path(".build/security/synthetic")
    else:
        findings, kev, exceptions, failures, statuses, coverage = real_inputs(
            args.evidence, date.today())
        output = args.evidence
    if os.getenv("SECURITY_PREREQUISITES_OK", "true") != "true":
        failures.append("Source/assembly integrity or scanner installation failed")
    try:
        decision = evaluate(findings, kev, exceptions, failures, synthetic=synthetic)
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        decision = evaluate([], set(), [], [f"Invalid policy metadata: {error}"],
                            synthetic=synthetic)
    decision["scenario"] = args.scenario
    output.mkdir(parents=True, exist_ok=True)
    (output / "decision.json").write_text(json.dumps(decision, indent=2) + "\n")
    summary = markdown(decision, statuses, coverage, args.scenario)
    (output / "summary.md").write_text(summary)
    print(summary)
    for variable, content in (("GITHUB_STEP_SUMMARY", summary), ("GITHUB_OUTPUT",
                              f"release_eligible={str(decision['release_eligible']).lower()}\n")):
        if path := os.getenv(variable):
            with open(path, "a") as stream:
                stream.write(content)
    return int(decision["result"] == "BLOCK")


if __name__ == "__main__":
    raise SystemExit(main())
