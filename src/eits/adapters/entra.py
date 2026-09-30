"""Microsoft Graph v1.0 sign-in and directory-audit object adapters."""

import ipaddress
import json
import re
from datetime import datetime, timezone

from ..model import Event, canonical, event_uid, object_at, text_at


def graph_records(content, format_name, expected_format):
    if format_name != expected_format:
        raise ValueError(f"unsupported file format: {format_name}")
    value = json.loads(content)
    if not isinstance(value, dict):
        raise ValueError("expected a Graph object or value collection")
    if "value" in value:
        if not isinstance(value["value"], list):
            raise ValueError("Graph value must be an array")
        records = ((f"/value/{index}", raw) for index, raw in enumerate(value["value"]))
    else:
        records = iter((("", value),))
    for pointer, raw in records:
        if not isinstance(raw, dict):
            raise ValueError("Graph record must be an object")
        yield pointer, raw


def timestamp_at(raw, field, quality):
    stamp = text_at(raw, field)
    if stamp is None:
        quality.append("missing_event_time")
        return None, None
    precision = re.search(r"T\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?(?:Z|[+-]\d{2}:\d{2})$", stamp)
    if precision is None:
        raise ValueError(f"{field} requires RFC3339 timezone and <=9 fractional digits")
    try:
        timestamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {field}") from exc
    if timestamp.tzinfo is None:
        raise ValueError(f"{field} must contain a timezone")
    nanos = int((precision.group(1) or "").ljust(9, "0")[6:])
    if nanos:
        quality.append("timestamp_submicrosecond_precision_in_extensions")
    return timestamp.astimezone(timezone.utc), nanos


def collection_tenant(context, quality):
    scope = context.collection_scope if context else None
    if scope and scope.scope_type not in (None, "azure.tenant"):
        raise ValueError("Entra collection scope must be azure.tenant")
    scope_id = scope.scope_id if scope else None
    tenant_id = scope.tenant_id if scope else None
    if scope_id and tenant_id and scope_id != tenant_id:
        raise ValueError("Entra scope_id and tenant_id must describe the same collection tenant")
    tenant = scope_id or tenant_id
    if tenant is None:
        quality.append("missing_collection_tenant")
    return tenant


def address_fields(address, quality):
    if address:
        try:
            return address, str(ipaddress.ip_address(address))
        except ValueError:
            quality.append("source_address_is_not_ip")
    return address, None


class _GraphAdapter:
    provider = "azure"

    def parse(self, content, format_name):
        return graph_records(content, format_name, self.formats[0])

    def resolve(self, content, format_name, pointer):
        matches = [
            raw for candidate, raw in self.parse(content, format_name) if candidate == pointer
        ]
        if len(matches) != 1:
            raise ValueError("source record pointer must resolve to exactly one record")
        return matches[0]

    def common(self, raw, context, time_field):
        if not isinstance(raw, dict):
            raise ValueError("Graph record must be an object")
        if context and (context.provider, context.source) != (self.provider, self.source):
            raise ValueError("normalization context provider/source mismatch")
        quality = []
        tenant = collection_tenant(context, quality)
        timestamp, nanos = timestamp_at(raw, time_field, quality)
        source_id = text_at(raw, "id")
        if not source_id:
            quality.append("missing_source_event_id")
        return {
            "event_uid": event_uid(
                self.provider,
                self.source,
                raw,
                scope_type="azure.tenant",
                scope_id=tenant,
                tenant_id=tenant,
            ),
            "provider": self.provider,
            "source": self.source,
            "scope_type": "azure.tenant",
            "scope_id": tenant,
            "tenant_id": tenant,
            "source_event_id": source_id,
            "timestamp": timestamp,
            "raw": canonical(raw),
            # Keep every source-specific field, including unknown future properties.
            "extensions": canonical({"graph": raw, "timestamp_submicrosecond_ns": nanos}),
        }, quality


class EntraSignInAdapter(_GraphAdapter):
    source = "azure.entra.signin"
    formats = ("graph-signin-json",)

    def normalize(self, raw, *, context=None):
        fields, quality = self.common(raw, context, "createdDateTime")
        error_code = object_at(raw, "status").get("errorCode")
        if isinstance(error_code, int) and not isinstance(error_code, bool):
            outcome = "success" if error_code == 0 else "failure"
        else:
            outcome = "unknown"
            quality.append("missing_or_invalid_status_error_code")
        actor = text_at(raw, "userId")
        if actor is None:
            quality.append("missing_actor_id")
        address, ip = address_fields(text_at(raw, "ipAddress"), quality)
        resources = []
        for key in ("appId", "resourceId"):
            if text_at(raw, key):
                resources.append({"type": key, "id": raw[key]})
        return Event(
            **fields,
            service="Microsoft Entra ID",
            action="signIn",
            actor_id=actor,
            actor_type="User" if actor else None,
            source_address=address,
            source_ip=ip,
            outcome=outcome,
            error_code=str(error_code) if outcome == "failure" else None,
            resources=canonical(resources),
            authentication=canonical(
                {
                    "mfa_authenticated": None,
                    "conditionalAccessStatus": raw.get("conditionalAccessStatus"),
                    "status": raw.get("status"),
                    "isInteractive": raw.get("isInteractive"),
                }
            ),
            quality=canonical(quality),
        )


class EntraAuditAdapter(_GraphAdapter):
    source = "azure.entra.audit"
    formats = ("graph-directory-audit-json",)

    def normalize(self, raw, *, context=None):
        fields, quality = self.common(raw, context, "activityDateTime")
        initiated = object_at(raw, "initiatedBy")
        user, app = object_at(initiated, "user"), object_at(initiated, "app")
        actor, actor_type = None, None
        if user and app:
            quality.append("ambiguous_initiator")
        elif text_at(user, "id"):
            actor, actor_type = user["id"], "User"
        elif text_at(app, "servicePrincipalId"):
            actor, actor_type = app["servicePrincipalId"], "ServicePrincipal"
        if actor is None:
            quality.append("missing_actor_id")
        address, ip = address_fields(text_at(user, "ipAddress"), quality)
        outcome = raw.get("result") if raw.get("result") in ("success", "failure") else "unknown"
        if outcome == "unknown":
            quality.append("missing_or_unknown_result")
        action = text_at(raw, "activityDisplayName")
        if action is None:
            quality.append("missing_action")
        targets = raw.get("targetResources")
        return Event(
            **fields,
            service="Microsoft Entra ID",
            action=action or "unknown",
            actor_id=actor,
            actor_type=actor_type,
            source_address=address,
            source_ip=ip,
            outcome=outcome,
            resources=canonical(targets if isinstance(targets, list) else []),
            quality=canonical(quality),
        )
