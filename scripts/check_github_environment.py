"""Disable AWS deployment until server-side branch/environment protection exists."""

import json
import os
import re
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen


def deployment_ready(repository: str, fetch) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid GitHub repository name")
    base = f"https://api.github.com/repos/{repository}"
    try:
        environment = fetch(base + "/environments/sandbox")
        branches = fetch(base + "/environments/sandbox/deployment-branch-policies")
        branch = fetch(base + "/branches/main")
    except HTTPError as error:
        if error.code == 404:
            return False
        raise
    policy = environment.get("deployment_branch_policy") or {}
    allowed = {(p["name"], p.get("type", "branch")) for p in branches["branch_policies"]}
    checks = branch.get("protection", {}).get("required_status_checks", {})
    contexts = set(checks.get("contexts", []))
    contexts.update(check["context"] for check in checks.get("checks", []))
    return (
        "Validate team" in contexts
        and policy.get("custom_branch_policies") is True
        and allowed == {("main", "branch")}
        and branch.get("protected") is True
    )


def fetch_json(url: str) -> dict:
    # The caller builds URLs only from the fixed HTTPS GitHub API origin.
    with urlopen(url, timeout=20) as response:  # nosec B310
        return json.load(response)


if __name__ == "__main__":
    ready = deployment_ready(os.environ["GITHUB_REPOSITORY"], fetch_json)
    print(
        "Sandbox deployment enabled"
        if ready
        else "Deployment disabled: require Validate team on main; restrict sandbox to main"
    )
    if output := os.getenv("GITHUB_OUTPUT"):
        with Path(output).open("a") as stream:
            stream.write(f"ready={str(ready).lower()}\n")
