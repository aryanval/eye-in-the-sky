"""CloudTrail mappings derived solely from linked public AWS documentation."""

import ipaddress
import json
from datetime import datetime, timezone

from ..model import Event, canonical, digest, object_at, text_at


def cloudtrail_records(content, format_name):
    if format_name == "jsonl":
        for line_number, line in enumerate(content.decode("utf-8").splitlines(), 1):
            if line.strip():
                yield f"line:{line_number}", json.loads(line)
    elif format_name == "cloudtrail-json":
        value = json.loads(content)
        if isinstance(value, dict) and isinstance(value.get("Records"), list):
            for index, record in enumerate(value["Records"]):
                yield f"/Records/{index}", record
        elif isinstance(value, dict) and "Records" not in value:
            yield "", value
        else:
            raise ValueError("expected a CloudTrail object or Records array")
    else:
        raise ValueError(f"unsupported file format: {format_name}")


def normalize_cloudtrail(raw):
    if not isinstance(raw, dict):
        raise ValueError("CloudTrail record must be an object")
    if not text_at(raw, "eventSource") or not text_at(raw, "eventName"):
        raise ValueError("CloudTrail record requires eventSource and eventName")
    identity = object_at(raw, "userIdentity")
    session = object_at(identity, "sessionContext")
    attributes = object_at(session, "attributes")
    request, response = object_at(raw, "requestParameters"), object_at(raw, "responseElements")
    quality, timestamp = [], None
    stamp = text_at(raw, "eventTime")
    if stamp:
        try:
            timestamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid eventTime") from exc
        if timestamp.tzinfo is None:
            raise ValueError("eventTime must contain a timezone")
        timestamp = timestamp.astimezone(timezone.utc)
    else:
        quality.append("missing_event_time")
    event_id = text_at(raw, "eventID")
    if not event_id:
        quality.append("missing_source_event_id")
    account = text_at(raw, "recipientAccountId") or text_at(identity, "accountId")
    if not account:
        quality.append("missing_account")
    address, source_ip = text_at(raw, "sourceIPAddress"), None
    if address:
        try:
            source_ip = str(ipaddress.ip_address(address))
        except ValueError:
            quality.append("source_address_is_not_ip")
    error = text_at(raw, "errorCode") or text_at(response, "errorCode")
    error_message = text_at(raw, "errorMessage") or text_at(response, "errorMessage")
    if error or error_message or response.get("_return") is False:
        outcome = "failure"
    elif raw.get("eventType") == "AwsApiCall":
        outcome = "success"  # Completed API record reporting no error; not proof of lasting state.
    else:
        outcome = "unknown"
    mfa = attributes.get("mfaAuthenticated")
    mfa_observed = {"true": True, "false": False}.get(mfa) if isinstance(mfa, str) else None
    resources = list(raw["resources"]) if isinstance(raw.get("resources"), list) else []
    for name in ("groupId", "userName", "roleName", "name", "policyArn"):
        if text_at(request, name):
            resources.append(
                {"type": name, "value": request[name], "field": f"/requestParameters/{name}"}
            )
    return Event(
        **{
            "event_uid": "evt_" + digest(canonical(raw).encode()),
            "source_event_id": event_id,
            "timestamp": timestamp,
            "provider": "aws",
            "source": "aws.cloudtrail",
            "scope_type": "aws.account",
            "scope_id": account,
            "tenant_id": None,
            "account_id": account,
            "region": text_at(raw, "awsRegion"),
            "actor_id": text_at(identity, "principalId"),
            "actor_type": text_at(identity, "type"),
            "actor_arn": text_at(identity, "arn"),
            "credential_id": text_at(identity, "accessKeyId"),
            "source_address": address,
            "source_ip": source_ip,
            "service": raw["eventSource"],
            "action": raw["eventName"],
            "outcome": outcome,
            "error_code": error,
            "resources": canonical(resources),
            "authentication": canonical(
                {"mfa_authenticated": mfa_observed, "session_context": session}
            ),
            "privilege_context": canonical({"session_issuer": object_at(session, "sessionIssuer")}),
            "extensions": canonical(
                {
                    "eventVersion": raw.get("eventVersion"),
                    "userIdentity": identity,
                    "requestParameters": raw.get("requestParameters"),
                    "responseElements": raw.get("responseElements"),
                }
            ),
            "raw": canonical(raw),
            "quality": canonical(quality),
        }
    )


class CloudTrailAdapter:
    provider = "aws"
    source = "aws.cloudtrail"
    formats = ("cloudtrail-json", "jsonl")

    def parse(self, content, format_name):
        return cloudtrail_records(content, format_name)

    def normalize(self, raw, *, context=None):
        return normalize_cloudtrail(raw)

    def resolve(self, content, format_name, pointer):
        matches = [
            raw for candidate, raw in self.parse(content, format_name) if candidate == pointer
        ]
        if len(matches) != 1:
            raise ValueError("source record pointer must resolve to exactly one record")
        return matches[0]
