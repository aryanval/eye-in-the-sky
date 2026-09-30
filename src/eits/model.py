"""Shared event contract, with opaque provider-qualified identity and scope."""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime


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


def event_uid(provider, source, raw, *, scope_type=None, scope_id=None, tenant_id=None):
    """Keep published AWS IDs; all other source domains use a disjoint v2 ID."""
    if (provider, source) == ("aws", "aws.cloudtrail"):
        return "evt_" + digest(canonical(raw).encode())
    return "evt_v2_" + digest(
        canonical(
            ["eits.event.v2", provider, source, scope_type, scope_id, tenant_id, raw]
        ).encode()
    )


@dataclass(frozen=True)
class Scope:
    scope_type: str | None = None
    scope_id: str | None = None
    tenant_id: str | None = None

    def validate(self, *, scope_types, has_tenant):
        if any(
            value is not None and (not isinstance(value, str) or not value)
            for value in asdict(self).values()
        ):
            raise ValueError("scope values must be nonempty strings or null")
        if self.scope_type is not None and self.scope_type not in scope_types:
            raise ValueError("scope_type is not valid for its source")
        if self.scope_id is not None and self.scope_type is None:
            raise ValueError("scope_id requires scope_type")
        if not has_tenant and self.tenant_id is not None:
            raise ValueError("tenant_id is not meaningful for this source")


@dataclass(frozen=True)
class NormalizationContext:
    provider: str
    source: str
    dataset_id: str
    collection_scope: Scope | None = None


@dataclass(frozen=True)
class Event:
    event_uid: str
    provider: str
    source: str
    service: str
    action: str
    raw: str
    source_event_id: str | None = None
    timestamp: datetime | None = None
    scope_type: str | None = None
    scope_id: str | None = None
    tenant_id: str | None = None
    account_id: str | None = None
    region: str | None = None
    actor_id: str | None = None
    actor_type: str | None = None
    actor_arn: str | None = None
    credential_id: str | None = None
    source_address: str | None = None
    source_ip: str | None = None
    outcome: str = "unknown"
    error_code: str | None = None
    resources: str = "[]"
    authentication: str = "{}"
    privilege_context: str = "{}"
    extensions: str = "{}"
    quality: str = "[]"

    def as_record(self):
        return asdict(self)

    def validate(self, *, provider, source, raw, scope_types, has_tenant):
        if not isinstance(raw, dict):
            raise ValueError("source record must be an object")
        if (self.provider, self.source) != (provider, source):
            raise ValueError("adapter event provider/source differs from manifest")
        if self.event_uid != event_uid(
            provider,
            source,
            raw,
            scope_type=self.scope_type,
            scope_id=self.scope_id,
            tenant_id=self.tenant_id,
        ):
            raise ValueError("adapter event UID violates source identity scheme")
        for name, value in self.as_record().items():
            if name == "timestamp":
                if value is not None and (
                    not isinstance(value, datetime)
                    or value.tzinfo is None
                    or value.utcoffset() is None
                ):
                    raise ValueError("event timestamp must contain a timezone")
            elif value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"event {name} must be a nonempty string or null")
        for name in ("provider", "source", "service", "action", "raw"):
            if not getattr(self, name):
                raise ValueError(f"event requires {name}")
        Scope(self.scope_type, self.scope_id, self.tenant_id).validate(
            scope_types=scope_types, has_tenant=has_tenant
        )
        if self.outcome not in {"success", "failure", "unknown"}:
            raise ValueError("unknown event outcome")
        for name, shape in (
            ("raw", dict),
            ("resources", list),
            ("authentication", dict),
            ("privilege_context", dict),
            ("extensions", dict),
            ("quality", list),
        ):
            try:
                value = json.loads(getattr(self, name))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"event {name} must be valid JSON") from exc
            if not isinstance(value, shape):
                raise ValueError(f"event {name} has invalid JSON shape")
        if canonical(json.loads(self.raw)) != canonical(raw):
            raise ValueError("adapter raw record differs from source artifact")


def normalize(raw):
    """Compatibility entry point for the published Phase-1 CloudTrail mapping."""
    from .adapters.aws import normalize_cloudtrail

    return normalize_cloudtrail(raw).as_record()
