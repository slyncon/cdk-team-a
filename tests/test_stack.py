import pytest
from aws_cdk import App
from aws_cdk.assertions import Match, Template
from cdk_launchpad.constructs import DocumentProcessor, SecureBucket
from cdk_launchpad.security import validate_template

from stack import ClaimsTeamStack


@pytest.fixture
def stack(tmp_path):
    return ClaimsTeamStack(App(outdir=str(tmp_path / "assembly")), "ClaimsTeamStack")


def test_platform_consumption_and_stack_security(stack):
    assert isinstance(stack.node.find_child("Documents"), SecureBucket)
    assert isinstance(stack.node.find_child("Processor"), DocumentProcessor)
    template = Template.from_stack(stack)
    template.resource_count_is("AWS::S3::Bucket", 1)
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Handler": "index.handler",
            "Runtime": "python3.12",
            "MemorySize": 128,
            "Timeout": 10,
            "Environment": {"Variables": {"TEAM": "claims"}},
        },
    )
    template.has_resource_properties("AWS::Logs::LogGroup", {"RetentionInDays": 7})
    assert validate_template(template.to_json()) == []


def test_resource_identity_and_notification_wiring(stack):
    template = Template.from_stack(stack)
    # These are compatibility checks for the existing construct paths.
    bucket_id = "DocumentsBucket089EA665"
    function_id = "ProcessorFunction5B2A90E2"
    assert set(template.find_resources("AWS::S3::Bucket")) == {bucket_id}
    template.has_output("BucketName", {"Value": {"Ref": bucket_id}})
    template.has_output("FunctionName", {"Value": {"Ref": function_id}})
    template.has_output("LogGroupName", {"Value": Match.any_value()})
    template.has_resource_properties(
        "Custom::S3BucketNotifications",
        {
            "BucketName": {"Ref": bucket_id},
            "NotificationConfiguration": {
                "LambdaFunctionConfigurations": [
                    {
                        "Events": ["s3:ObjectCreated:*"],
                        "LambdaFunctionArn": {"Fn::GetAtt": [function_id, "Arn"]},
                        "Filter": Match.any_value(),
                    }
                ]
            },
        },
    )
    assert "Fn::ImportValue" not in str(template.to_json())
