"""Disable AWS deployment until server-side branch/environment protection exists."""

import json
import os
import re
from http.client import HTTPSConnection
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit


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
    # Enforce the fixed origin at the network boundary, including redirects/schemes.
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "api.github.com"
        or not parsed.path.startswith("/repos/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Only fixed-origin GitHub repository API URLs are allowed")
    connection = HTTPSConnection("api.github.com", timeout=20)
    try:
        connection.request("GET", parsed.path, headers={"User-Agent": "claims-ci"})
        response = connection.getresponse()
        if response.status != 200:
            raise HTTPError(url, response.status, response.reason, response.headers, None)
        return json.load(response)
    finally:
        connection.close()


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
