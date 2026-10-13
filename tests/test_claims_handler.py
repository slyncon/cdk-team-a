import importlib.util
import io
import json
import logging
from pathlib import Path
from unittest.mock import Mock, call

import pytest

# Load this team's handler by path so both standalone projects can be tested together.
TEAM_DIRECTORY = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "teamA_handler", TEAM_DIRECTORY / "handler" / "index.py"
)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
FIXTURE = TEAM_DIRECTORY / "fixtures" / "claim.json"


def event(*keys):
    return {
        "Records": [
            {"s3": {"bucket": {"name": "synthetic-test-bucket"}, "object": {"key": key}}}
            for key in keys
        ]
    }


def mock_s3(monkeypatch, module, payload):
    # A fresh stream for each read also lets duplicate events run safely twice.
    s3 = Mock(spec=["get_object"])
    s3.get_object.side_effect = lambda **kwargs: {"Body": io.BytesIO(payload)}
    client = Mock(return_value=s3)
    monkeypatch.setattr(module.boto3, "client", client)
    return s3, client


def test_success_multiple_records_decoding_and_read_only(monkeypatch, caplog):
    payload = FIXTURE.read_bytes()
    s3, client = mock_s3(monkeypatch, module, payload)
    with caplog.at_level(logging.INFO):
        result = module.handler(
            event("incoming%2Ffake+document.json", "incoming/second.json"), None
        )
    assert result == {"processed": 2}
    client.assert_called_once_with("s3")
    assert s3.mock_calls == [
        call.get_object(Bucket="synthetic-test-bucket", Key="incoming/fake document.json"),
        call.get_object(Bucket="synthetic-test-bucket", Key="incoming/second.json"),
    ]
    expected = {
        "team": "claims",
        "document_id": json.loads(payload)["claim_id"],
        "result": "processed",
    }
    assert [json.loads(record.message) for record in caplog.records] == [expected, expected]


def test_duplicate_event_is_safe(monkeypatch):
    s3, _ = mock_s3(monkeypatch, module, FIXTURE.read_bytes())
    notification = event("incoming/document.json")
    assert module.handler(notification, None) == {"processed": 1}
    assert module.handler(notification, None) == {"processed": 1}
    assert s3.get_object.call_count == 2


@pytest.mark.parametrize(
    "payload,message",
    [
        (b"invalid", "valid JSON"),
        (b"[]", "JSON object"),
        (b"null", "JSON object"),
    ],
)
def test_malformed_document(monkeypatch, payload, message):
    mock_s3(monkeypatch, module, payload)
    with pytest.raises(ValueError, match=message):
        module.handler(event("incoming/bad.json"), None)


@pytest.mark.parametrize("replacement", [None, "", "  ", 123, False])
def test_required_string_types(monkeypatch, replacement):
    document = json.loads(FIXTURE.read_text())
    # Check every field, not just the document identifier.
    fields = ("claim_id", "category")
    for field in fields:
        invalid = dict(document)
        if replacement is None:
            del invalid[field]
        else:
            invalid[field] = replacement
        mock_s3(monkeypatch, module, json.dumps(invalid).encode())
        with pytest.raises(ValueError, match=field):
            module.handler(event("incoming/bad.json"), None)


@pytest.mark.parametrize("amount", [None, True, "45.50", -1, float("nan"), float("inf")])
def test_claim_amount_validation(monkeypatch, amount):
    document = json.loads(FIXTURE.read_text())
    document["amount_eur"] = amount
    mock_s3(monkeypatch, module, json.dumps(document).encode())
    with pytest.raises(ValueError, match="amount_eur"):
        module.handler(event("incoming/bad.json"), None)


def test_s3_failure_is_not_reported_as_success(monkeypatch, caplog):
    s3, _ = mock_s3(monkeypatch, module, b"{}")
    s3.get_object.side_effect = RuntimeError("S3 read failed")
    with pytest.raises(RuntimeError, match="S3 read failed"):
        module.handler(event("incoming/document.json"), None)
    assert not caplog.records
