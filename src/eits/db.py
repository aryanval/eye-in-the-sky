"""Manifest-checked local ingestion through source adapters; no cloud dependencies."""

import json
import re
from importlib.resources import files
from pathlib import Path

import duckdb

from .adapters import DEFAULT_REGISTRY
from .model import Event, NormalizationContext, Scope, canonical, digest
from .model import event_uid as identify_event

KINDS = {"official sample", "synthetic", "public dataset", "personally generated live event"}
SCHEMA_VERSION = "2"


def connect(path=":memory:"):
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = duckdb.connect(str(path), config={"enable_external_access": "false"})
    try:
        connection.execute("SET TimeZone='UTC'")
        connection.execute("BEGIN TRANSACTION")
        try:
            tables = {row[0] for row in connection.execute("SHOW TABLES").fetchall()}
            if not tables:
                connection.execute(files("eits").joinpath("sql/schema.sql").read_text())
            else:
                version = (
                    connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()
                    if "metadata" in tables
                    else None
                )
                if version is None or version[0] not in {"1", SCHEMA_VERSION}:
                    raise ValueError("unsupported database schema")
                if version[0] == "1":
                    connection.execute(
                        files("eits").joinpath("sql/schema-v1-to-v2.sql").read_text()
                    )
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
    except Exception:
        connection.close()
        raise
    return connection


def rows(connection, sql, parameters=None):
    cursor = connection.execute(sql, parameters or [])
    columns = [x[0] for x in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def records(content, format_name):
    """Compatibility wrapper for the original CloudTrail record iterator."""
    return DEFAULT_REGISTRY.get("aws", "aws.cloudtrail").parse(content, format_name)


def validate_manifest(manifest, registry=DEFAULT_REGISTRY):
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    required = (
        "dataset_id",
        "provider",
        "source",
        "category",
        "source_urls",
        "license",
        "modified",
        "limitations",
        "files",
    )
    if any(key not in manifest for key in required):
        raise ValueError("manifest missing mandatory provenance fields")
    if not isinstance(manifest["category"], str) or manifest["category"] not in KINDS:
        raise ValueError("unknown provenance category")
    if (
        not isinstance(manifest["source_urls"], list)
        or not manifest["source_urls"]
        or not all(
            isinstance(url, str) and url.startswith("https://") for url in manifest["source_urls"]
        )
        or not isinstance(manifest["license"], str)
        or not manifest["license"]
        or not isinstance(manifest["files"], list)
        or not manifest["files"]
    ):
        raise ValueError("manifest must declare source URLs, license, and files")
    if (
        not isinstance(manifest["modified"], bool)
        or not isinstance(manifest["limitations"], list)
        or not all(isinstance(item, str) for item in manifest["limitations"])
    ):
        raise ValueError("modified must be boolean and limitations must be a list of strings")
    for name in ("dataset_id", "provider", "source"):
        if not isinstance(manifest[name], str) or not manifest[name]:
            raise ValueError(f"{name} must be a nonempty string")
    seen = set()
    for spec in manifest["files"]:
        if (
            not isinstance(spec, dict)
            or not all(key in spec for key in ("path", "sha256", "format"))
            or not isinstance(spec["path"], str)
            or not spec["path"]
        ):
            raise ValueError("each file requires path, sha256, and format")
        if (
            not isinstance(spec["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", spec["sha256"])
            or not isinstance(spec["format"], str)
            or not spec["format"]
        ):
            raise ValueError("each file requires a SHA-256 hex digest and a nonempty format")
        if spec["path"] in seen:
            raise ValueError("manifest file paths must be unique")
        seen.add(spec["path"])
    adapter = registry.get(manifest["provider"], manifest["source"])
    normalization_context(manifest, registry)
    if any(spec["format"] not in adapter.formats for spec in manifest["files"]):
        raise ValueError("unsupported file format for source adapter")
    return adapter


def normalization_context(manifest, registry=DEFAULT_REGISTRY):
    declared = manifest.get("collection_scope")
    scope = None
    if declared is not None:
        if (
            not isinstance(declared, dict)
            or not declared
            or set(declared) - {"scope_type", "scope_id", "tenant_id"}
        ):
            raise ValueError(
                "collection_scope requires only scope_type, scope_id, and/or tenant_id"
            )
        scope = Scope(**declared)
        spec = registry.spec(manifest["provider"], manifest["source"])
        scope.validate(scope_types=spec.scope_types, has_tenant=spec.has_tenant)
    return NormalizationContext(
        manifest["provider"], manifest["source"], manifest["dataset_id"], scope
    )


def ingest(connection, manifest_path, *, registry=DEFAULT_REGISTRY):
    path = Path(manifest_path).resolve()
    manifest = json.loads(path.read_text())
    adapter = validate_manifest(manifest, registry)
    source_spec = registry.spec(manifest["provider"], manifest["source"])
    context = normalization_context(manifest, registry)
    manifest_sha = digest(canonical(manifest).encode())
    existing = connection.execute(
        "SELECT manifest_sha256 FROM datasets WHERE dataset_id=?", [manifest["dataset_id"]]
    ).fetchone()
    if existing and existing[0] != manifest_sha:
        raise ValueError(
            "dataset_id already imported with a different manifest; use a versioned dataset ID"
        )
    count_before = connection.execute("SELECT count(*) FROM events").fetchone()[0]
    processed = 0
    connection.execute("BEGIN TRANSACTION")
    try:
        connection.execute(
            "INSERT INTO datasets VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
            [manifest["dataset_id"], canonical(manifest), manifest_sha],
        )
        for spec in manifest["files"]:
            file_path = (path.parent / spec["path"]).resolve()
            if not file_path.is_relative_to(path.parent):
                raise ValueError("fixture path must remain inside its manifest directory")
            content = file_path.read_bytes()
            sha = digest(content)
            if sha != spec["sha256"]:
                raise ValueError(f"SHA-256 mismatch: {spec['path']}")
            connection.execute(
                "INSERT INTO artifacts VALUES (?, ?) ON CONFLICT DO NOTHING", [sha, content]
            )
            pointers = set()
            for pointer, raw in adapter.parse(content, spec["format"]):
                if not isinstance(pointer, str) or pointer in pointers:
                    raise ValueError(
                        "source record pointers must be unique strings within an artifact"
                    )
                pointers.add(pointer)
                raw_snapshot = canonical(raw)
                normalized = adapter.normalize(raw, context=context)
                if canonical(raw) != raw_snapshot:
                    raise ValueError("adapter normalization must not modify source record")
                if not isinstance(normalized, Event):
                    raise ValueError("adapter must normalize each record to an Event")
                normalized.validate(
                    provider=manifest["provider"],
                    source=manifest["source"],
                    raw=raw,
                    scope_types=source_spec.scope_types,
                    has_tenant=source_spec.has_tenant,
                )
                event = normalized.as_record()
                if context.collection_scope is not None:
                    for key in ("scope_type", "scope_id", "tenant_id"):
                        declared = getattr(context.collection_scope, key)
                        if declared is not None and event[key] != declared:
                            raise ValueError(
                                "adapter event scope differs from manifest collection scope"
                            )
                if event["source_event_id"]:
                    conflict = connection.execute(
                        """SELECT event_uid FROM events WHERE provider=? AND source=?
                        AND scope_type IS NOT DISTINCT FROM ? AND scope_id IS NOT DISTINCT FROM ?
                        AND tenant_id IS NOT DISTINCT FROM ? AND source_event_id=? AND event_uid<>?""",
                        [
                            event[key]
                            for key in (
                                "provider",
                                "source",
                                "scope_type",
                                "scope_id",
                                "tenant_id",
                                "source_event_id",
                                "event_uid",
                            )
                        ],
                    ).fetchone()
                    if conflict:
                        raise ValueError(
                            f"conflicting payload for source event ID {event['source_event_id']}"
                        )
                columns, marks = ",".join(event), ",".join("?" for _ in event)
                connection.execute(
                    f"INSERT INTO events ({columns}) VALUES ({marks}) ON CONFLICT DO NOTHING",
                    list(event.values()),
                )
                connection.execute(
                    "INSERT INTO occurrences VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                    [manifest["dataset_id"], sha, spec["path"], pointer, event["event_uid"]],
                )
                processed += 1
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    count_after = connection.execute("SELECT count(*) FROM events").fetchone()[0]
    return {
        "dataset_id": manifest["dataset_id"],
        "records_processed": processed,
        "new_events": count_after - count_before,
        "total_events": count_after,
    }


def evidence(connection, event_uid, *, registry=DEFAULT_REGISTRY):
    found = rows(connection, "SELECT * FROM events WHERE event_uid=?", [event_uid])
    if not found:
        raise ValueError(f"unknown event: {event_uid}")
    event = found[0]
    for key in ("raw", "quality", "resources", "authentication", "privilege_context", "extensions"):
        event[key] = json.loads(event[key])
    if (
        identify_event(
            event["provider"],
            event["source"],
            event["raw"],
            scope_type=event["scope_type"],
            scope_id=event["scope_id"],
            tenant_id=event["tenant_id"],
        )
        != event_uid
    ):
        raise ValueError("stored event identity integrity check failed")
    refs = rows(
        connection,
        """SELECT o.dataset_id, o.artifact_sha256, o.source_path, o.record_pointer,
        d.manifest, d.manifest_sha256 FROM occurrences o JOIN datasets d USING(dataset_id) WHERE o.event_uid=?
        ORDER BY o.dataset_id, o.source_path, o.record_pointer""",
        [event_uid],
    )
    if not refs:
        raise ValueError("event has no source artifact references")
    for ref in refs:
        manifest = json.loads(ref.pop("manifest"))
        if digest(canonical(manifest).encode()) != ref.pop("manifest_sha256"):
            raise ValueError("stored manifest integrity check failed")
        adapter = validate_manifest(manifest, registry)
        if (manifest["provider"], manifest["source"]) != (event["provider"], event["source"]):
            raise ValueError("event source differs from artifact manifest")
        context = normalization_context(manifest, registry)
        if context.collection_scope is not None:
            for key in ("scope_type", "scope_id", "tenant_id"):
                declared = getattr(context.collection_scope, key)
                if declared is not None and event[key] != declared:
                    raise ValueError("event scope differs from artifact manifest collection scope")
        ref["category"], ref["source_urls"] = manifest["category"], manifest["source_urls"]
        artifact = connection.execute(
            "SELECT content FROM artifacts WHERE sha256=?", [ref["artifact_sha256"]]
        ).fetchone()
        if artifact is None or digest(bytes(artifact[0])) != ref["artifact_sha256"]:
            raise ValueError("stored artifact integrity check failed")
        content = bytes(artifact[0])
        spec = next(
            (item for item in manifest["files"] if item["path"] == ref["source_path"]), None
        )
        if spec is None or spec["sha256"] != ref["artifact_sha256"]:
            raise ValueError("source reference differs from artifact manifest")
        raw = adapter.resolve(content, spec["format"], ref["record_pointer"])
        if canonical(raw) != canonical(event["raw"]):
            raise ValueError("normalized raw record differs from source artifact")
        ref["integrity_verified"] = True
    event["source_references"] = refs
    return event
