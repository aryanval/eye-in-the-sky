"""Google Cloud LogEntry/AuditLog JSON, with explicit log-owning scope."""

import ipaddress
import json
import re
from datetime import datetime, timezone

from ..model import Event, canonical, event_uid, object_at, text_at

AUDIT_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"
SCOPE_TYPES = {
    "projects": "gcp.project",
    "organizations": "gcp.organization",
    "folders": "gcp.folder",
}


class GcpAuditAdapter:
    provider = "gcp"
    source = "gcp.audit"
    formats = ("gcp-audit-json",)

    def parse(self, content, format_name):
        if format_name not in self.formats:
            raise ValueError("unsupported GCP file format")
        value = json.loads(content)
        if isinstance(value, list):
            yield from ((f"/{index}", raw) for index, raw in enumerate(value))
        elif isinstance(value, dict) and "entries" in value:
            if not isinstance(value["entries"], list):
                raise ValueError("GCP entries must be an array")
            yield from ((f"/entries/{index}", raw) for index, raw in enumerate(value["entries"]))
        elif isinstance(value, dict):
            yield "", value
        else:
            raise ValueError("expected GCP LogEntry object, array or entries envelope")

    def normalize(self, raw, *, context=None):
        if not isinstance(raw, dict):
            raise ValueError("GCP LogEntry must be an object")
        payload = object_at(raw, "protoPayload")
        if payload.get("@type") != AUDIT_TYPE:
            raise ValueError("GCP protoPayload must be a typed AuditLog")
        service, action = text_at(payload, "serviceName"), text_at(payload, "methodName")
        if not service or not action:
            raise ValueError("GCP AuditLog requires serviceName and methodName")
        quality, stamp = [], text_at(raw, "timestamp")
        submicrosecond_nanos = 0
        timestamp = None
        if stamp:
            precision = re.search(
                r"T\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?(?:Z|[+-]\d{2}:\d{2})$", stamp
            )
            if precision is None:
                raise ValueError(
                    "GCP timestamp requires RFC3339 timezone and <=9 fractional digits"
                )
            try:
                timestamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("invalid GCP timestamp") from exc
            if timestamp.tzinfo is None:
                raise ValueError("GCP timestamp must contain a timezone")
            timestamp = timestamp.astimezone(timezone.utc)
            submicrosecond_nanos = int((precision.group(1) or "").ljust(9, "0")[6:])
        else:
            quality.append("missing_event_time")
        log_name = text_at(raw, "logName")
        scope_type, scope_id = None, None
        if log_name:
            match = re.fullmatch(r"(projects|organizations|folders)/([^/]+)/logs/([^/]+)", log_name)
            if match:
                scope_type, scope_id = SCOPE_TYPES[match[1]], match[2]
            else:
                quality.append("unsupported_log_scope")
        if scope_id is None:
            quality.append("missing_scope")
        # insertId is not globally unique. Keep nanosecond text in this identity;
        # DuckDB/Python timestamp precision is lower and is not an identity input.
        insert_id = text_at(raw, "insertId")
        source_id = canonical([insert_id, stamp]) if insert_id and stamp else None
        if source_id is None:
            quality.append("missing_source_event_id")
        auth, request_meta = (
            object_at(payload, "authenticationInfo"),
            object_at(payload, "requestMetadata"),
        )
        address = text_at(request_meta, "callerIp")
        source_ip = None
        if address:
            try:
                source_ip = str(ipaddress.ip_address(address))
            except ValueError:
                quality.append("source_address_is_not_ip")
        status = payload.get("status")
        code = status.get("code") if isinstance(status, dict) else None
        outcome, error_code = "unknown", None
        if isinstance(code, int) and not isinstance(code, bool):
            outcome = "success" if code == 0 else "failure"
            error_code = str(code) if code else None
        elif status == {}:
            outcome = "success"
        else:
            quality.append("unknown_outcome")
        operation = object_at(raw, "operation")
        if operation and operation.get("last") is not True and outcome == "success":
            outcome = "unknown"
            quality.append("operation_completion_unknown")
        resource_name = text_at(payload, "resourceName")
        return Event(
            event_uid=event_uid(
                self.provider, self.source, raw, scope_type=scope_type, scope_id=scope_id
            ),
            provider=self.provider,
            source=self.source,
            scope_type=scope_type,
            scope_id=scope_id,
            timestamp=timestamp,
            source_event_id=source_id,
            service=service,
            action=action,
            actor_id=text_at(auth, "principalSubject"),
            credential_id=text_at(auth, "serviceAccountKeyName"),
            source_address=address,
            source_ip=source_ip,
            outcome=outcome,
            error_code=error_code,
            resources=canonical(
                [{"type": "gcp.resource", "value": resource_name}] if resource_name else []
            ),
            authentication=canonical(auth),
            privilege_context=canonical({"authorizationInfo": payload.get("authorizationInfo")}),
            extensions=canonical(
                {
                    "logName": raw.get("logName"),
                    "insertId": raw.get("insertId"),
                    "resource": raw.get("resource"),
                    "protoPayload": payload,
                    "operation": raw.get("operation"),
                    "timestamp": raw.get("timestamp"),
                    "submicrosecond_nanos": submicrosecond_nanos if stamp else None,
                }
            ),
            raw=canonical(raw),
            quality=canonical(quality),
        )

    def resolve(self, content, format_name, pointer):
        matches = [
            raw for candidate, raw in self.parse(content, format_name) if candidate == pointer
        ]
        if len(matches) != 1:
            raise ValueError("source record pointer must resolve to exactly one record")
        return matches[0]
