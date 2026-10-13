"""Read-only processing of synthetic claims. Duplicate events are harmless."""

import json
import logging
import math
import os
from urllib.parse import unquote_plus

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def handler(event: dict, context: object) -> dict:
    s3 = boto3.client("s3")
    processed = 0
    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])
        response = s3.get_object(Bucket=bucket, Key=key)
        with response["Body"] as body:
            try:
                document = json.load(body)
            except (ValueError, UnicodeDecodeError) as error:
                raise ValueError("Claim document must contain valid JSON") from error
        if not isinstance(document, dict):
            raise ValueError("Claim document must be a JSON object")
        for field in ("claim_id", "category"):
            if not isinstance(document.get(field), str) or not document[field].strip():
                raise ValueError(f"Claim document requires a nonempty string: {field}")
        amount = document.get("amount_eur")
        if type(amount) not in (int, float) or not math.isfinite(amount) or amount < 0:
            raise ValueError("Claim document requires a finite nonnegative number: amount_eur")
        logger.info(
            json.dumps(
                {
                    "team": os.getenv("TEAM", "claims"),
                    "document_id": document["claim_id"],
                    "result": "processed",
                }
            )
        )
        processed += 1
    return {"processed": processed}
