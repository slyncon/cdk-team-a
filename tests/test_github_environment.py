import pytest

from scripts.check_github_environment import deployment_ready, fetch_json


@pytest.mark.parametrize(
    "protected,allowed,expected",
    [
        (True, "main", True),
        (False, "main", False),
        (True, "*", False),
    ],
)
def test_deployment_requires_protected_main_and_exact_environment_branch(
    protected, allowed, expected
):
    def fetch(url):
        if url.endswith("deployment-branch-policies"):
            return {"branch_policies": [{"name": allowed, "type": "branch"}]}
        if url.endswith("branches/main"):
            return {
                "protected": protected,
                "protection": {"required_status_checks": {"contexts": ["Validate team"]}},
            }
        return {"deployment_branch_policy": {"custom_branch_policies": True}}

    assert deployment_ready("example/claims", fetch) is expected


def test_branch_protection_without_required_validation_is_insufficient():
    def fetch(url):
        if url.endswith("deployment-branch-policies"):
            return {"branch_policies": [{"name": "main", "type": "branch"}]}
        if url.endswith("branches/main"):
            return {"protected": True}
        return {"deployment_branch_policy": {"custom_branch_policies": True}}

    assert not deployment_ready("example/claims", fetch)


def test_missing_environment_keeps_deployment_disabled():
    from urllib.error import HTTPError

    def fetch(url):
        raise HTTPError(url, 404, "Not found", None, None)

    assert not deployment_ready("example/claims", fetch)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://api.github.com/repos/example/claims",
        "https://evil.example/repos/example/claims",
        "https://api.github.com@evil.example/repos/example/claims",
        "https://api.github.com/repos/example/claims?redirect=elsewhere",
    ],
)
def test_fetch_rejects_untrusted_origins_before_network(url):
    with pytest.raises(ValueError, match="fixed-origin"):
        fetch_json(url)


def test_fetch_json_uses_verified_https_and_closes_connection(monkeypatch):
    import io

    class Connection:
        def __init__(self, host, timeout):
            assert host == "api.github.com" and timeout == 20

        def request(self, method, path, headers):
            assert method == "GET" and path == "/repos/example/claims"

        def getresponse(self):
            response = io.BytesIO(b'{"protected": true}')
            response.status = 200
            return response

        def close(self):
            closed.append(True)

    closed = []
    monkeypatch.setattr("scripts.check_github_environment.HTTPSConnection", Connection)
    assert fetch_json("https://api.github.com/repos/example/claims") == {"protected": True}
    assert closed == [True]
