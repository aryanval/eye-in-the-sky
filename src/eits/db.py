"""Manifest-checked local ingestion; no network or cloud SDK dependencies."""
import json
from importlib.resources import files
from pathlib import Path

import duckdb

from .model import canonical, digest, normalize

KINDS = {"official sample", "synthetic", "public dataset", "personally generated live event"}


def connect(path=":memory:"):
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = duckdb.connect(str(path), config={"enable_external_access": "false"})
    connection.execute("SET TimeZone='UTC'")
    connection.execute(files("eits").joinpath("sql/schema.sql").read_text())
    if connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0] != "1":
        raise ValueError("unsupported database schema")
    return connection


def rows(connection, sql, parameters=None):
    cursor = connection.execute(sql, parameters or [])
    columns = [x[0] for x in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def records(content, format_name):
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
            yield "/", value
        else:
            raise ValueError("expected a CloudTrail object or Records array")
    else:
        raise ValueError(f"unsupported file format: {format_name}")


def ingest(connection, manifest_path):
    path = Path(manifest_path).resolve()
    manifest = json.loads(path.read_text())
    required = ("dataset_id", "provider", "source", "category", "source_urls", "license", "modified", "limitations", "files")
    if any(key not in manifest for key in required):
        raise ValueError("manifest missing mandatory provenance fields")
    if manifest["category"] not in KINDS:
        raise ValueError("unknown provenance category")
    if manifest["provider"] != "aws" or manifest["source"] != "aws.cloudtrail":
        raise ValueError("Phase 1 supports only AWS CloudTrail")
    if not manifest["source_urls"] or not manifest["license"] or not manifest["files"]:
        raise ValueError("manifest must declare source URLs, license, and files")
    manifest_sha = digest(canonical(manifest).encode())
    existing = connection.execute("SELECT manifest_sha256 FROM datasets WHERE dataset_id=?", [manifest["dataset_id"]]).fetchone()
    if existing and existing[0] != manifest_sha:
        raise ValueError("dataset_id already imported with a different manifest; use a versioned dataset ID")
    count_before = connection.execute("SELECT count(*) FROM events").fetchone()[0]
    processed = 0
    connection.execute("BEGIN TRANSACTION")
    try:
        connection.execute("INSERT INTO datasets VALUES (?, ?, ?) ON CONFLICT DO NOTHING", [manifest["dataset_id"], canonical(manifest), manifest_sha])
        for spec in manifest["files"]:
            file_path = (path.parent / spec["path"]).resolve()
            if not file_path.is_relative_to(path.parent):
                raise ValueError("fixture path must remain inside its manifest directory")
            content = file_path.read_bytes()
            sha = digest(content)
            if sha != spec["sha256"]:
                raise ValueError(f"SHA-256 mismatch: {spec['path']}")
            connection.execute("INSERT INTO artifacts VALUES (?, ?) ON CONFLICT DO NOTHING", [sha, content])
            for pointer, raw in records(content, spec["format"]):
                event = normalize(raw)
                if event["source_event_id"]:
                    conflict = connection.execute(
                        "SELECT event_uid FROM events WHERE account_id IS NOT DISTINCT FROM ? AND source_event_id=? AND event_uid<>?",
                        [event["account_id"], event["source_event_id"], event["event_uid"]]).fetchone()
                    if conflict:
                        raise ValueError(f"conflicting payload for source event ID {event['source_event_id']}")
                columns, marks = ",".join(event), ",".join("?" for _ in event)
                connection.execute(f"INSERT INTO events ({columns}) VALUES ({marks}) ON CONFLICT DO NOTHING", list(event.values()))
                connection.execute("INSERT INTO occurrences VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING", [manifest["dataset_id"], sha, spec["path"], pointer, event["event_uid"]])
                processed += 1
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    count_after = connection.execute("SELECT count(*) FROM events").fetchone()[0]
    return {"dataset_id": manifest["dataset_id"], "records_processed": processed,
            "new_events": count_after - count_before, "total_events": count_after}


def evidence(connection, event_uid):
    found = rows(connection, "SELECT * FROM events WHERE event_uid=?", [event_uid])
    if not found:
        raise ValueError(f"unknown event: {event_uid}")
    event = found[0]
    for key in ("raw", "quality", "resources", "authentication", "privilege_context", "extensions"):
        event[key] = json.loads(event[key])
    refs = rows(connection, """SELECT o.dataset_id, o.artifact_sha256, o.source_path, o.record_pointer,
        d.manifest FROM occurrences o JOIN datasets d USING(dataset_id) WHERE o.event_uid=?
        ORDER BY o.dataset_id, o.source_path, o.record_pointer""", [event_uid])
    for ref in refs:
        manifest = json.loads(ref.pop("manifest"))
        ref["category"], ref["source_urls"] = manifest["category"], manifest["source_urls"]
        content = bytes(connection.execute("SELECT content FROM artifacts WHERE sha256=?", [ref["artifact_sha256"]]).fetchone()[0])
        if digest(content) != ref["artifact_sha256"]:
            raise ValueError("stored artifact integrity check failed")
        spec = next(x for x in manifest["files"] if x["path"] == ref["source_path"])
        raw = next(r for p, r in records(content, spec["format"]) if p == ref["record_pointer"])
        if canonical(raw) != canonical(event["raw"]):
            raise ValueError("normalized raw record differs from source artifact")
        ref["integrity_verified"] = True
    event["source_references"] = refs
    return event
