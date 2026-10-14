from pathlib import Path

from aws_cdk import ArnFormat, CfnOutput, Stack, Tags
from aws_cdk import aws_iam as iam
from cdk_launchpad.constructs import DocumentProcessor, SecureBucket
from constructs import Construct


class ClaimsTeamStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        Tags.of(self).add("Project", "CDKLaunchpad")
        Tags.of(self).add("Environment", "Demo")
        Tags.of(self).add("Team", "claims")
        documents = SecureBucket(self, "Documents")
        processor = DocumentProcessor(
            self,
            "Processor",
            bucket=documents.bucket,
            handler_directory=str(Path(__file__).parent / "handler"),
            team="claims",
        )
        # Stack-owned ceiling: no external policy or deleted deployment-role dependency.
        boundary = iam.ManagedPolicy(
            self,
            "RuntimeBoundary",
            description="Claims runtime ceiling for S3 reads, notification setup and logs",
            statements=[
                iam.PolicyStatement(
                    actions=["s3:GetBucket*", "s3:ListBucket", "s3:PutBucketNotification"],
                    resources=[documents.bucket.bucket_arn],
                ),
                iam.PolicyStatement(
                    actions=["s3:GetObject*"],
                    resources=[documents.bucket.arn_for_objects("incoming/*")],
                ),
                iam.PolicyStatement(
                    actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    resources=[
                        processor.function.log_group.log_group_arn,
                        self.format_arn(
                            service="logs",
                            resource="log-group",
                            resource_name=f"/aws/lambda/{self.stack_name}-*",
                            arn_format=ArnFormat.COLON_RESOURCE_NAME,
                        ),
                    ],
                ),
            ],
        )
        iam.PermissionsBoundary.of(self).apply(boundary)
        CfnOutput(self, "BucketName", value=documents.bucket.bucket_name)
        CfnOutput(self, "FunctionName", value=processor.function.function_name)
        CfnOutput(self, "LogGroupName", value=processor.function.log_group.log_group_name)
