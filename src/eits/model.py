"""CloudTrail mappings derived solely from linked public AWS documentation."""
import hashlib
import ipaddress
import json
from datetime import datetime, timezone


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(content):
    return hashlib.sha256(content).hexdigest()


def object_at(value, key):
    result = value.get(key)
    return result if isinstance(result, dict) else {}


def text_at(value, key):
    result = value.get(key)
    return result if isinstance(result, str) and result else None


def normalize(raw):
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
            resources.append({"type": name, "value": request[name], "field": f"/requestParameters/{name}"})
    return {
        "event_uid": "evt_" + digest(canonical(raw).encode()), "source_event_id": event_id,
        "timestamp": timestamp, "provider": "aws", "source": "aws.cloudtrail",
        "account_id": account, "region": text_at(raw, "awsRegion"),
        "actor_id": text_at(identity, "principalId"), "actor_type": text_at(identity, "type"),
        "actor_arn": text_at(identity, "arn"), "credential_id": text_at(identity, "accessKeyId"),
        "source_address": address, "source_ip": source_ip, "service": raw["eventSource"],
        "action": raw["eventName"], "outcome": outcome, "error_code": error,
        "resources": canonical(resources),
        "authentication": canonical({"mfa_authenticated": mfa_observed, "session_context": session}),
        "privilege_context": canonical({"session_issuer": object_at(session, "sessionIssuer")}),
        "extensions": canonical({"eventVersion": raw.get("eventVersion"), "userIdentity": identity,
                                  "requestParameters": raw.get("requestParameters"),
                                  "responseElements": raw.get("responseElements")}),
        "raw": canonical(raw), "quality": canonical(quality),
    }
