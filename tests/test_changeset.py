import copy

import pytest

from scripts.check_changeset import check_changeset


@pytest.fixture
def changeset():
    return {
        "StackId": "arn:aws:cloudformation:eu-central-1:000000000000:stack/ClaimsTeamStack/example",
        "Status": "CREATE_COMPLETE",
        "Changes": [
            {
                "ResourceChange": {
                    "ResourceType": "AWS::S3::Bucket",
                    "LogicalResourceId": "DocumentsBucket",
                    "Action": "Modify",
                    "Replacement": "False",
                }
            }
        ],
    }


def test_safe_change_passes(changeset):
    assert check_changeset(changeset, "000000000000", "eu-central-1")


@pytest.mark.parametrize(
    "action,replacement", [("Remove", "False"), ("Modify", "True"), ("Modify", "Conditional")]
)
def test_bucket_loss_is_rejected(changeset, action, replacement):
    resource = changeset["Changes"][0]["ResourceChange"]
    resource.update(Action=action, Replacement=replacement)
    with pytest.raises(ValueError, match="bucket removal/replacement"):
        check_changeset(changeset, "000000000000", "eu-central-1")


def test_wrong_target_and_failed_change_set_are_rejected(changeset):
    with pytest.raises(ValueError, match="configured sandbox"):
        check_changeset(changeset, "111111111111", "eu-central-1")
    failed = copy.deepcopy(changeset)
    failed.update(Status="FAILED", StatusReason="Insufficient permissions")
    with pytest.raises(ValueError, match="Insufficient permissions"):
        check_changeset(failed, "000000000000", "eu-central-1")
    failed["StatusReason"] = "The submitted information didn't contain changes."
    assert not check_changeset(failed, "000000000000", "eu-central-1")
