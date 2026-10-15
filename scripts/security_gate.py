"""Small fail-closed release decision over scanner JSON; no AWS or third-party imports."""

import argparse
import copy
import json
import os
import re
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = (
    "real",
    "clean",
    "high-cvss",
    "kev",
    "exception-approved",
    "exception-expired",
    "combined-risk",
)
SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def load(path):
    return json.loads(Path(path).read_text())


def kev_ids(catalog, today):
    """Only real mode calls this: validated, recent official CISA download."""
    entries = catalog["vulnerabilities"]
    released = date.fromisoformat(catalog["dateReleased"][:10])
    if (
        not catalog["catalogVersion"]
        or not entries
        or catalog["count"] != len(entries)
        or not today - timedelta(days=30) <= released <= today
    ):
        raise ValueError("CISA catalog is empty, inconsistent, stale or future-dated")
    ids = {entry["cveID"] for entry in entries}
    if not all(re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) for cve in ids):
        raise ValueError("Invalid CVE identifier in CISA catalog")
    return ids


def cvss_scores(vulnerability):
    scores = []
    for source, values in vulnerability.get("CVSS", {}).items():
        for field, version in (("V2Score", "2.0"), ("V3Score", "3.x"), ("V40Score", "4.0")):
            if field in values:
                score = values[field]
                if not isinstance(score, (float, int)) or not 0 <= score <= 10:
                    raise ValueError("Invalid numeric CVSS score")
                # Prefer the precise vector version when the scanner supplies it.
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
            if severity not in SEVERITIES:
                raise ValueError("Unknown severity value")
            findings.append(
                {
                    "id": item.get("VulnerabilityID") or item["ID"],
                    "kind": kind,
                    "severity": severity,
                "component": item.get("PkgName")
                or item.get("CauseMetadata", {}).get("Resource", item.get("Type", "IaC")),
                    "scope": result["Target"],
                    "cvss": cvss_scores(item),
                    "version": item.get("InstalledVersion", ""),
                    "fix": item.get("FixedVersion", ""),
                }
            )
    return findings


def exception_status(finding, exceptions, today):
    for item in exceptions:
        if item.get("id") != finding["id"]:
            continue
        required = ("id", "paths", "component", "statement", "owner", "approved_by", "expired_at")
        status = "invalid metadata"
        if all(item.get(key) for key in required):
            if item["owner"].casefold() == item["approved_by"].casefold():
                status = "requires independent approver"
            elif item["paths"] != [finding["scope"]] or item["component"] != finding["component"]:
                status = "scope mismatch"
            elif not re.fullmatch(r"\d{4}-\d{2}-\d{2}T00:00:00Z", item["expired_at"]):
                status = "invalid expiry (use UTC midnight timestamp)"
            elif date.fromisoformat(item["expired_at"][:10]) <= today:
                status = "expired"
            else:
                status = "valid"
        return status, item
    return "none", {}


def evaluate(findings, kev, exceptions, failures=(), *, synthetic=False, today=None):
    today = today or date.today()
    reasons = list(failures)
    reviewed = []
    for original in findings:
        item = copy.deepcopy(original)
        item["kev"] = item["id"] in kev
        status, exception = exception_status(item, exceptions, today)
        if item["kev"]:
            reasons.append(
                f"{item['id']}: CISA KEV match cannot be waived"
                if not synthetic
                else f"{item['id']}: mocked KEV match cannot be waived"
            )
            status = "not permitted for KEV"
        elif item["kind"] == "sast":
            reasons.append(f"{item['id']}: configured Semgrep security rule")
            status = "not permitted for SAST"
        elif item["severity"] in {"HIGH", "CRITICAL"} or any(
            score["score"] >= 7 for score in item["cvss"]
        ):
            if status != "valid":
                reasons.append(
                    f"{item['id']}: {item['severity']} / CVSS policy; exception {status}"
                )
        item.update(exception_status=status, exception=exception)
        reviewed.append(item)
    result = (
        "BLOCK"
        if reasons
        else (
            "ALLOW WITH EXCEPTION"
            if any(f["exception_status"] == "valid" for f in reviewed)
            else "PASS"
        )
    )
    return {
        "mode": "SYNTHETIC / PRESENTATION ONLY" if synthetic else "REAL SCAN",
        "result": result,
        "reasons": reasons,
        "findings": reviewed,
        "release_eligible": not synthetic and result != "BLOCK",
    }


def check_coverage(evidence, reports, semgrep):
    """A scanner returning zero findings must still prove it inspected the intended inputs."""
    coverage = load(evidence / "coverage.json")
    scanned = set(semgrep["paths"]["scanned"])
    expected = {"handler/index.py", "app.py", "stack.py"}
    if not expected <= scanned or not semgrep.get("version"):
        raise ValueError("Semgrep did not scan the handler and both CDK definitions")
    actual_packages = {
        (r["Target"], p["Name"], p["Version"])
        for r in reports["dependencies"].get("Results", [])
        for p in r.get("Packages", [])
    }
    if not set(map(tuple, coverage["expected_packages"])) <= actual_packages:
        raise ValueError("Trivy skipped one or more locked Python/npm dependencies")
    iac = reports["iac"]
    if not any(
        r["Type"] == "cloudformation"
        and r.get("MisconfSummary", {}).get("Successes", 0)
        + r.get("MisconfSummary", {}).get("Failures", 0)
        > 0
        for r in iac.get("Results", [])
    ):
        raise ValueError("Trivy did not evaluate synthesized CloudFormation checks")
    if coverage["runtime_files"] != ["index.py"] or coverage["runtime_packages"] != 0:
        raise ValueError(
            "Lambda packaging changed: update the runtime inventory and coverage check"
        )
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
    failures, findings, coverage = [], [], {}
    statuses = {}
    # All mandatory steps are recorded, including report conversions and intelligence retrieval.
    mandatory = {
        "semgrep",
        "dependencies",
        "iac",
        "runtime",
        "dependencies-sbom",
        "runtime-sbom",
        "dependencies-readable",
        "iac-readable",
        "runtime-readable",
        "kev",
    }
    try:
        statuses = dict(
            line.split("\t") for line in (evidence / "status.tsv").read_text().splitlines()
        )
        failures.extend(
            f"Mandatory scanner/evidence failure: {key} (exit {statuses.get(key, 'missing')})"
            for key in sorted(mandatory)
            if statuses.get(key) != "0"
        )
    except (OSError, ValueError) as error:
        failures.append(f"Missing scanner completion evidence: {error}")
    try:
        semgrep = load(evidence / "semgrep.json")
        if semgrep["errors"]:
            failures.append("Semgrep reported scan errors; findings differ from scanner failure")
        for item in semgrep["results"]:
            findings.append(
                {
                    "id": item["check_id"],
                    "kind": "sast",
                    "scope": item["path"],
                    "component": "Python source",
                    "severity": {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}[
                        item["extra"]["severity"]
                    ],
                    "cvss": [],
                }
            )
        reports = {
            key: load(evidence / f"{key}.json") for key in ("dependencies", "iac", "runtime")
        }
        for key, report in reports.items():
            findings.extend(
                trivy_findings(report, "misconfiguration" if key == "iac" else "dependency")
            )
        coverage = check_coverage(evidence, reports, semgrep)
        kev = kev_ids(load(evidence / "kev.json"), today)
        config = load(ROOT / "security/trivyignore.yaml")  # JSON is a native YAML subset.
        exceptions = config["vulnerabilities"] + config["misconfigurations"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        failures.append(f"Missing or invalid required evidence: {error}")
        kev, exceptions = set(), []
    return findings, kev, exceptions, failures, statuses, coverage


def demo_inputs(scenario):
    fixture = load(ROOT / "security/scenarios.json")
    findings = [copy.deepcopy(fixture["findings"][key]) for key in fixture["scenarios"][scenario]]
    exceptions = []
    if scenario.startswith("exception-"):
        exceptions = [copy.deepcopy(fixture["exception"])]
        if scenario == "exception-expired":
            exceptions[0]["expired_at"] = "2000-01-01T00:00:00Z"
    return findings, set(fixture["mock_kev"]), exceptions


def markdown(decision, statuses, coverage):
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")

    synthetic = decision["mode"].startswith("SYNTHETIC")
    counts = Counter(f["severity"] for f in decision["findings"])
    lines = [
        f"## {decision['mode']}",
        f"**Result: {decision['result']}**",
        "",
        "Release eligible: **" + ("Yes" if decision["release_eligible"] else "No") + "**",
        "",
    ]
    if synthetic:
        lines += [
            "SYNTHETIC DEMONSTRATION — actual scanners were not run in this job. "
            "Fictional CVEs and an explicitly mocked KEV catalog; no genuine CISA match. "
            "BLOCK is an expected red Security Scan job. This can never approve a release.",
            "",
        ]
    lines += ["| Check | Status |", "|---|---|"]
    for label, key in (
        ("Semgrep", "semgrep"),
        ("Trivy dependencies", "dependencies"),
        ("Trivy infrastructure", "iac"),
        ("Trivy Lambda artifact", "runtime"),
    ):
        state = (
            "MOCKED / PRESENTATION ONLY"
            if synthetic
            else (
                "Completed (see findings)"
                if statuses.get(key) == "0"
                else "FAILED / missing evidence"
            )
        )
        lines.append(f"| {label} | {state} |")
    lines += [
        "",
        "Findings: "
        + ", ".join(
            f"{key.title()} **{counts[key]}**"
            for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        ),
        "",
        "| ID | Severity | Component / scope | CVSS (source, version) | "
        "CISA KEV match | Exception / owner / approver / expiry |",
        "|---|---|---|---|---|---|",
    ]
    for f in decision["findings"]:
        scores = "; ".join(f"{s['score']} ({s['source']}, v{s['version']})" for s in f["cvss"])
        exception = f["exception"]
        exception_text = " / ".join(
            str(exception.get(key, "—")) for key in ("owner", "approved_by", "expired_at")
        )
        kev = ("Yes (MOCKED)" if synthetic else "Yes") if f["kev"] else "No"
        lines.append(
            "| "
            + " | ".join(
                map(
                    cell,
                    [
                        f["id"],
                        f["severity"],
                        f"{f['component']} / {f['scope']}",
                        scores or "Not provided",
                        kev,
                        f"{f['exception_status']} / {exception_text}",
                    ],
                )
            )
            + " |"
        )
    lines += [
        "",
        "**Reasons:** " + ("; ".join(map(cell, decision["reasons"])) or "No blocking findings."),
    ]
    if coverage:
        lines += [
            "",
            f"Coverage: {len(coverage['expected_packages'])} locked Python/npm packages; "
            "synthesized CloudFormation; staged Claims index.py verified against source. "
            "Zero bundled third-party runtime packages. AWS-managed boto3 is outside CI inventory.",
        ]
    lines += [
        "",
        "**Next action:** "
        + (
            "Compare the expected outcome in SECURITY_DEMO.md. Run real to assess code."
            if synthetic
            else "Review downloadable JSON and SBOMs; upgrade affected packages or fix code/IaC. "
            "Repair failed scanners and rerun. Request a reviewed, expiring exception if justified."
        ),
    ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, default="real")
    parser.add_argument("--evidence", type=Path, default=Path(".build/security/real"))
    args = parser.parse_args()
    synthetic = args.scenario != "real"
    statuses, coverage = {}, {}
    if synthetic:
        findings, kev, exceptions = demo_inputs(args.scenario)
        failures = []
        # Synthetic mode never reads or writes real scanner evidence.
        output = Path(".build/security/synthetic")
    else:
        findings, kev, exceptions, failures, statuses, coverage = real_inputs(
            args.evidence, date.today()
        )
        output = args.evidence
    if os.getenv("SECURITY_PREREQUISITES_OK", "true") != "true":
        failures.append("Source/assembly integrity or scanner installation failed")
    try:
        decision = evaluate(findings, kev, exceptions, failures, synthetic=synthetic)
    except (ValueError, KeyError, TypeError) as error:
        decision = evaluate(
            [], set(), [], [f"Invalid policy metadata: {error}"], synthetic=synthetic
        )
    output.mkdir(parents=True, exist_ok=True)
    (output / "decision.json").write_text(json.dumps(decision, indent=2) + "\n")
    summary = markdown(decision, statuses, coverage)
    (output / "summary.md").write_text(summary)
    print(summary)
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(summary)
    if os.getenv("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            stream.write(f"release_eligible={str(decision['release_eligible']).lower()}\n")
    return 1 if decision["result"] == "BLOCK" else 0


if __name__ == "__main__":
    raise SystemExit(main())
