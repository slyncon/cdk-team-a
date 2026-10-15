import socket

import boto3
import pytest


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    """Fail immediately on accidental network access or an unmocked AWS client."""

    def forbidden(*args, **kwargs):
        raise AssertionError("Offline tests must mock AWS clients and never use the network")

    monkeypatch.setattr(boto3, "client", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.delenv("TEAM", raising=False)
    # CLI tests must never publish their fixture reports into the build job.
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
