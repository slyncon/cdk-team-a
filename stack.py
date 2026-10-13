from pathlib import Path

from aws_cdk import CfnOutput, Stack, Tags
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
        CfnOutput(self, "BucketName", value=documents.bucket.bucket_name)
        CfnOutput(self, "FunctionName", value=processor.function.function_name)
        CfnOutput(self, "LogGroupName", value=processor.function.log_group.log_group_name)
