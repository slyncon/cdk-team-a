import pytest

from scripts.check_github_environment import deployment_ready


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
