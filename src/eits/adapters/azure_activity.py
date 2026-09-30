"""Azure Monitor REST EventData only; diagnostic export shapes are not accepted."""

import ipaddress
import json
import re
from dataclasses import asdict
from datetime import datetime, timezone

from ..model import Event, canonical, event_uid, object_at, text_at

OBJECT_ID = "http://schemas.microsoft.com/identity/claims/objectidentifier"
ACTOR_TENANT = "http://schemas.microsoft.com/identity/claims/tenantid"


class AzureActivityAdapter:
    provider = "azure"
    source = "azure.activity"
    formats = ("azure-activity-rest-json",)

    def parse(self, content, format_name):
        if format_name not in self.formats:
            raise ValueError("unsupported Azure Activity format")
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ValueError("expected an Azure REST EventData object or value collection")
        if "value" in value:
            if not isinstance(value["value"], list):
                raise ValueError("Azure REST value must be an array")
            for index, raw in enumerate(value["value"]):
                if not isinstance(raw, dict):
                    raise ValueError("Azure REST EventData must be an object")
                yield f"/value/{index}", raw
        else:
            yield "", value

    def normalize(self, raw, *, context=None):
        if not isinstance(raw, dict):
            raise ValueError("Azure REST EventData must be an object")
        action = text_at(object_at(raw, "operationName"), "value")
        if not action:
            raise ValueError("Azure REST EventData requires operationName.value")
        claims, quality = object_at(raw, "claims"), []
        subscription, tenant = text_at(raw, "subscriptionId"), text_at(raw, "tenantId")
        collection = context.collection_scope if context is not None else None
        if collection is not None:
            if collection.scope_type not in {None, "azure.subscription"}:
                raise ValueError("Azure subscription REST parser requires subscription scope")
            for name, observed, declared in (
                ("subscription", subscription, collection.scope_id),
                ("tenant", tenant, collection.tenant_id),
            ):
                if observed is not None and declared is not None and observed != declared:
                    raise ValueError(f"Azure {name} differs from collection scope")
            subscription = subscription or collection.scope_id
            tenant = tenant or collection.tenant_id
        scope = {"scope_type": "azure.subscription", "scope_id": subscription, "tenant_id": tenant}
        timestamp, stamp = None, text_at(raw, "eventTimestamp")
        submicrosecond_ns = None
        if stamp:
            precision = re.search(
                r"T\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?(?:Z|[+-]\d{2}:\d{2})$", stamp
            )
            if precision is None:
                raise ValueError(
                    "Azure eventTimestamp requires RFC3339 timezone and <=9 fractional digits"
                )
            try:
                timestamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("invalid Azure eventTimestamp") from exc
            if timestamp.tzinfo is None:
                raise ValueError("Azure eventTimestamp must contain a timezone")
            timestamp = timestamp.astimezone(timezone.utc)
            submicrosecond_ns = int((precision.group(1) or "").ljust(9, "0")[6:])
            if submicrosecond_ns:
                quality.append("timestamp_submicrosecond_precision_in_extensions")
        source_id, actor = text_at(raw, "eventDataId"), text_at(claims, OBJECT_ID)
        for label, value in (
            ("event_time", timestamp),
            ("source_event_id", source_id),
            ("subscription", subscription),
            ("tenant", tenant),
            ("actor_object_id", actor),
            ("actor_tenant_id", text_at(claims, ACTOR_TENANT)),
        ):
            if value is None:
                quality.append("missing_" + label)
        address = text_at(object_at(raw, "httpRequest"), "clientIpAddress")
        source_ip = None
        if address:
            try:
                source_ip = str(ipaddress.ip_address(address))
            except ValueError:
                quality.append("source_address_is_not_ip")
        status = text_at(object_at(raw, "status"), "value")
        outcome = {"succeeded": "success", "failed": "failure"}.get(
            status.lower() if status else None, "unknown"
        )
        resource_id = text_at(raw, "resourceId")
        service = text_at(object_at(raw, "resourceProviderName"), "value")
        if not service:
            # Required common field names the known source, not an invented provider.
            service = "azure.monitor.activity"
            quality.append("missing_resource_provider")
        return Event(
            event_uid=event_uid(self.provider, self.source, raw, **scope),
            provider=self.provider,
            source=self.source,
            source_event_id=source_id,
            timestamp=timestamp,
            service=service,
            action=action,
            actor_id=actor,
            source_address=address,
            source_ip=source_ip,
            outcome=outcome,
            resources=canonical(
                [{"type": "azure.resource", "value": resource_id, "field": "/resourceId"}]
                if resource_id
                else []
            ),
            authentication=canonical({"claims": raw.get("claims")}),
            privilege_context=canonical({"authorization": raw.get("authorization")}),
            extensions=canonical(
                {
                    "actor_tenant_id": text_at(claims, ACTOR_TENANT),
                    "caller": raw.get("caller"),
                    "claims": raw.get("claims"),
                    "authorization": raw.get("authorization"),
                    "correlationId": raw.get("correlationId"),
                    "operationId": raw.get("operationId"),
                    "category": raw.get("category"),
                    "status": raw.get("status"),
                    "subStatus": raw.get("subStatus"),
                    "properties": raw.get("properties"),
                    "subscriptionId": raw.get("subscriptionId"),
                    "tenantId": raw.get("tenantId"),
                    "resourceProviderName": raw.get("resourceProviderName"),
                    "resourceGroupName": raw.get("resourceGroupName"),
                    "timestamp_submicrosecond_ns": submicrosecond_ns,
                    "collection_scope": asdict(collection) if collection is not None else None,
                }
            ),
            quality=canonical(quality),
            raw=canonical(raw),
            **scope,
        )

    def resolve(self, content, format_name, pointer):
        matches = [
            raw for candidate, raw in self.parse(content, format_name) if candidate == pointer
        ]
        if len(matches) != 1:
            raise ValueError("source record pointer must resolve to exactly one record")
        return matches[0]
