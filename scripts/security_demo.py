"""Synthesize a disposable policy demonstration; never deploy this stack."""

import argparse

from aws_cdk import App, Stack
from aws_cdk import aws_s3 as s3
from cdk_launchpad.constructs import SecureBucket


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["secure", "insecure"])
    args = parser.parse_args()
    app = App(outdir=".build/security-demo")
    stack = Stack(app, "SecurityDemo")
    if args.mode == "secure":
        SecureBucket(stack, "Documents")
    else:
        s3.Bucket(stack, "Bypass", encryption=s3.BucketEncryption.UNENCRYPTED)
    app.synth()


if __name__ == "__main__":
    main()
