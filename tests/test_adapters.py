"""Shared ingestion contracts; stub adapters are not Azure or GCP parsers."""

import copy
import json
import tempfile
import unittest
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import duckdb

from eits.adapters import AdapterRegistry, source_catalog
from eits.adapters.aws import CloudTrailAdapter
from eits.db import connect, evidence, ingest, rows
from eits.engine import detect
from eits.model import Event, canonical, digest, event_uid, normalize

ROOT = Path(__file__).resolve().parents[1]

# The actual Phase-1 schema, frozen independently from the current schema resource.
LEGACY_SCHEMA = """
CREATE TABLE metadata (key VARCHAR PRIMARY KEY, value VARCHAR NOT NULL);
INSERT INTO metadata VALUES ('schema_version', '1');
CREATE TABLE datasets (
    dataset_id VARCHAR PRIMARY KEY, manifest JSON NOT NULL, manifest_sha256 VARCHAR NOT NULL
);
CREATE TABLE artifacts (sha256 VARCHAR PRIMARY KEY, content BLOB NOT NULL);
CREATE TABLE events (
    event_uid VARCHAR PRIMARY KEY, source_event_id VARCHAR, timestamp TIMESTAMPTZ,
    provider VARCHAR NOT NULL, source VARCHAR NOT NULL, account_id VARCHAR, region VARCHAR,
    actor_id VARCHAR, actor_type VARCHAR, actor_arn VARCHAR, credential_id VARCHAR,
    source_address VARCHAR, source_ip VARCHAR, service VARCHAR NOT NULL, action VARCHAR NOT NULL,
    outcome VARCHAR NOT NULL, error_code VARCHAR, resources JSON NOT NULL,
    authentication JSON NOT NULL, privilege_context JSON NOT NULL, extensions JSON NOT NULL,
    raw JSON NOT NULL, quality JSON NOT NULL
);
CREATE TABLE occurrences (
    dataset_id VARCHAR NOT NULL, artifact_sha256 VARCHAR NOT NULL, source_path VARCHAR NOT NULL,
    record_pointer VARCHAR NOT NULL, event_uid VARCHAR NOT NULL,
    PRIMARY KEY (dataset_id, source_path, record_pointer)
);
"""


class StubAdapter:
    """Tiny private test format with no relationship to any vendor schema."""

    formats = ("test-only-json",)

    def __init__(
        self,
        provider="azure",
        source="azure.activity",
        scope_type="azure.subscription",
        scope_id=None,
        tenant_id=None,
    ):
        self.provider, self.source, self.scope_type = provider, source, scope_type
        self.scope_id, self.tenant_id = scope_id, tenant_id
        self.parsed = 0
        self.resolved = []

    def parse(self, content, format_name):
        self.parsed += 1
        for index, raw in enumerate(json.loads(content)):
            yield f"test-record:{index}", raw

    def normalize(self, raw, *, context=None):
        scope = {
            "scope_type": raw.get("scope_type", self.scope_type),
            "scope_id": raw.get("scope_id", self.scope_id),
            "tenant_id": raw.get("tenant_id", self.tenant_id),
        }
        if context is not None and context.collection_scope is not None:
            scope = asdict(context.collection_scope)
        return Event(
            event_uid=event_uid(self.provider, self.source, raw, **scope),
            provider=self.provider,
            source=self.source,
            service="test-service",
            action="test-action",
            raw=canonical(raw),
            source_event_id=raw["id"],
            **scope,
        )

    def resolve(self, content, format_name, pointer):
        self.resolved.append(pointer)
        matches = [
            raw for candidate, raw in self.parse(content, format_name) if candidate == pointer
        ]
        if len(matches) != 1:
            raise ValueError("invalid test record pointer")
        return matches[0]


def write_manifest(
    directory,
    events,
    *,
    provider="azure",
    source="azure.activity",
    dataset="stub",
    collection_scope=None,
):
    content = canonical(events).encode()
    filename = f"{dataset}.json"
    (directory / filename).write_bytes(content)
    manifest = {
        "dataset_id": dataset,
        "provider": provider,
        "source": source,
        "category": "synthetic",
        "source_urls": ["https://example.org/test-contract-only"],
        "license": "MIT",
        "modified": True,
        "limitations": ["Internal contract test, not a vendor schema fixture"],
        "files": [{"path": filename, "sha256": digest(content), "format": "test-only-json"}],
    }
    if collection_scope is not None:
        manifest["collection_scope"] = collection_scope
    path = directory / f"{dataset}-manifest.json"
    path.write_text(canonical(manifest))
    return path


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.connection = connect()
        self.addCleanup(self.connection.close)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.adapter = StubAdapter()
        self.registry = AdapterRegistry([CloudTrailAdapter(), self.adapter])

    def import_events(self, events, **kwargs):
        return ingest(
            self.connection, write_manifest(self.path, events, **kwargs), registry=self.registry
        )

    def test_catalog_separates_reserved_sources_from_implemented_parsers(self):
        catalog = source_catalog()
        self.assertEqual(
            [entry["source"] for entry in catalog if entry["implemented"]], ["aws.cloudtrail"]
        )
        self.assertEqual(len(catalog), 5)
        registry = AdapterRegistry()
        for entry in catalog[1:]:
            with (
                self.subTest(source=entry["source"]),
                self.assertRaisesRegex(ValueError, "not implemented"),
            ):
                registry.get(entry["provider"], entry["source"])
        with self.assertRaisesRegex(ValueError, "mismatch"):
            registry.get("gcp", "aws.cloudtrail")
        with self.assertRaisesRegex(ValueError, "unknown source"):
            registry.get("aws", "aws.unknown")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            AdapterRegistry([self.adapter, self.adapter])
        with self.assertRaisesRegex(ValueError, "requires"):
            AdapterRegistry(
                [
                    type(
                        "Incomplete",
                        (),
                        {"provider": "aws", "source": "aws.cloudtrail", "formats": ()},
                    )()
                ]
            )

    def test_identity_domains_and_legacy_aws_ids(self):
        raw = {"id": "identical-record"}
        legacy = "evt_" + digest(canonical(raw).encode())
        self.assertEqual(event_uid("aws", "aws.cloudtrail", raw), legacy)
        identities = [event_uid(item["provider"], item["source"], raw) for item in source_catalog()]
        self.assertEqual(len(set(identities)), 5)
        self.assertTrue(all(value.startswith("evt_v2_") for value in identities[1:]))

    def test_provider_and_source_ids_are_isolated_with_exact_artifact_resolution(self):
        adapters = [
            StubAdapter(),
            StubAdapter("azure", "azure.entra.signin", "azure.tenant"),
            StubAdapter("gcp", "gcp.audit", "gcp.project"),
        ]
        self.registry = AdapterRegistry([CloudTrailAdapter(), *adapters])
        aws_raw = json.loads((ROOT / "fixtures/aws/synthetic/case-01.json").read_text())["Records"][
            0
        ]
        ingest(self.connection, ROOT / "fixtures/aws/synthetic/manifest.json")
        for index, adapter in enumerate(adapters):
            result = self.import_events(
                [{"id": aws_raw["eventID"], "scope_id": aws_raw["recipientAccountId"]}],
                provider=adapter.provider,
                source=adapter.source,
                dataset=f"stub-{index}",
            )
            self.assertEqual(result["new_events"], 1)
            uid = self.connection.execute(
                "SELECT event_uid FROM events WHERE source=?", [adapter.source]
            ).fetchone()[0]
            resolved = evidence(self.connection, uid, registry=self.registry)
            self.assertTrue(resolved["source_references"][0]["integrity_verified"])
            self.assertEqual(adapter.resolved, ["test-record:0"])
            self.assertEqual(resolved["raw"]["id"], aws_raw["eventID"])

    def test_identical_raw_in_different_collection_scopes_never_deduplicates(self):
        raw = {"id": "same-source-id", "user": "same@example.org", "ip": "192.0.2.1"}
        for index, (scope_id, tenant_id) in enumerate(
            (("scope-a", "tenant-a"), ("scope-b", "tenant-a"), ("scope-a", "tenant-b"))
        ):
            adapter = StubAdapter()
            registry = AdapterRegistry([adapter])
            path = write_manifest(
                self.path,
                [raw],
                dataset=f"scoped-{index}",
                collection_scope={
                    "scope_type": "azure.subscription",
                    "scope_id": scope_id,
                    "tenant_id": tenant_id,
                },
            )
            self.assertEqual(ingest(self.connection, path, registry=registry)["new_events"], 1)
        events = rows(self.connection, "SELECT * FROM events")
        self.assertEqual(len({item["event_uid"] for item in events}), 3)
        self.assertEqual(len({item["raw"] for item in events}), 1)

    def test_scope_and_tenant_separate_conflict_domains(self):
        first = {"id": "same-id", "scope_id": "subscription-a", "tenant_id": "tenant-a"}
        events = [
            first,
            {**first, "scope_id": "subscription-b"},
            {**first, "tenant_id": "tenant-b"},
            {**first, "scope_type": "azure.tenant"},
        ]
        self.assertEqual(self.import_events(events)["new_events"], 4)
        changed = {**first, "changed_payload": True}
        with self.assertRaisesRegex(ValueError, "conflicting payload"):
            self.import_events([{"id": "fresh-id"}, changed], dataset="conflict")
        self.assertEqual(self.connection.execute("SELECT count(*) FROM events").fetchone()[0], 4)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM datasets").fetchone()[0], 1)

    def test_collection_scope_is_validated_and_adapter_must_preserve_it(self):
        for scope in (
            {"scope_id": "missing-type"},
            {"scope_type": "gcp.project"},
            {"tenant_id": []},
            {"email": "not-a-scope@example.org"},
        ):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                self.import_events([{"id": "one"}], collection_scope=scope)
        self.assertEqual(self.adapter.parsed, 0)
        path = write_manifest(
            self.path,
            [{"id": "one"}],
            collection_scope={"scope_type": "azure.subscription", "scope_id": "declared"},
        )
        original = self.adapter.normalize
        with patch.object(
            self.adapter, "normalize", side_effect=lambda raw, **kwargs: original(raw)
        ):
            with self.assertRaisesRegex(ValueError, "differs from manifest collection scope"):
                ingest(self.connection, path, registry=self.registry)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM datasets").fetchone()[0], 0)

    def test_unknown_scope_conflicts_conservatively_within_source(self):
        self.import_events([{"id": "same-id", "scope_type": None}])
        with self.assertRaisesRegex(ValueError, "conflicting payload"):
            self.import_events(
                [{"id": "same-id", "scope_type": None, "other": True}], dataset="unknown-conflict"
            )

    def test_duplicate_imports_and_artifact_survival(self):
        manifest = write_manifest(self.path, [{"id": "same-id"}])
        self.assertEqual(ingest(self.connection, manifest, registry=self.registry)["new_events"], 1)
        self.assertEqual(ingest(self.connection, manifest, registry=self.registry)["new_events"], 0)
        self.directory.cleanup()
        uid = self.connection.execute("SELECT event_uid FROM events").fetchone()[0]
        self.assertTrue(
            evidence(self.connection, uid, registry=self.registry)["source_references"][0][
                "integrity_verified"
            ]
        )

    def test_manifest_and_artifact_validation_precedes_parser(self):
        original = write_manifest(self.path, [{"id": "example"}])
        good = json.loads(original.read_text())
        for key, value in (
            ("license", None),
            ("provider", "aws"),
            ("modified", "yes"),
            ("limitations", [None]),
            ("source", []),
        ):
            with self.subTest(key=key):
                manifest = {**good, key: value}
                original.write_text(canonical(manifest))
                with self.assertRaises(ValueError):
                    ingest(self.connection, original, registry=self.registry)
        malformed_digest = copy.deepcopy(good)
        malformed_digest["files"][0]["sha256"] = "invalid"
        original.write_text(canonical(malformed_digest))
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            ingest(self.connection, original, registry=self.registry)
        original.write_text(canonical(good))
        (self.path / "stub.json").write_text("[]")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            ingest(self.connection, original, registry=self.registry)
        self.assertEqual(self.adapter.parsed, 0)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM datasets").fetchone()[0], 0)

    def test_normalized_contract_rejects_invalid_adapter_output(self):
        path = write_manifest(self.path, [{"id": "one"}])
        original = self.adapter.normalize
        changes = [
            {"provider": "gcp"},
            {"source": "azure.entra.audit"},
            {"event_uid": "evt_invalid"},
            {"raw": "{}"},
            {"scope_type": "gcp.project"},
            {"scope_type": None, "scope_id": "value"},
            {"timestamp": datetime(2025, 1, 1)},
            {"outcome": "maybe"},
            {"action": None},
            {"resources": "{}"},
            {"quality": "null"},
            {"source_event_id": 123},
        ]
        for change in changes:
            with self.subTest(change=change):
                with patch.object(
                    self.adapter,
                    "normalize",
                    side_effect=lambda raw, **kwargs: replace(original(raw), **change),
                ):
                    with self.assertRaises(ValueError):
                        ingest(self.connection, path, registry=self.registry)
                self.assertEqual(
                    self.connection.execute("SELECT count(*) FROM artifacts").fetchone()[0], 0
                )
        with patch.object(self.adapter, "normalize", return_value={}):
            with self.assertRaisesRegex(ValueError, "to an Event"):
                ingest(self.connection, path, registry=self.registry)

    def test_duplicate_record_pointers_roll_back(self):
        raw = {"id": "one"}
        path = write_manifest(self.path, [raw])
        with patch.object(self.adapter, "parse", return_value=[("same", raw), ("same", raw)]):
            with self.assertRaisesRegex(ValueError, "pointers"):
                ingest(self.connection, path, registry=self.registry)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM events").fetchone()[0], 0)

    def test_normalization_cannot_mutate_source_records(self):
        original = self.adapter.normalize

        def mutating(raw, **kwargs):
            raw["unexpected"] = True
            return original(raw, **kwargs)

        with patch.object(self.adapter, "normalize", side_effect=mutating):
            with self.assertRaisesRegex(ValueError, "must not modify"):
                self.import_events([{"id": "one"}])
        self.assertEqual(self.connection.execute("SELECT count(*) FROM events").fetchone()[0], 0)

    def test_evidence_detects_tampered_scope(self):
        self.import_events([{"id": "one", "scope_id": "correct"}])
        uid = self.connection.execute("SELECT event_uid FROM events").fetchone()[0]
        self.connection.execute("UPDATE events SET scope_id='wrong'")
        with self.assertRaisesRegex(ValueError, "event identity integrity"):
            evidence(self.connection, uid, registry=self.registry)

    def test_every_evidence_reference_matches_manifest_collection_scope(self):
        raw = {"id": "same-id", "user": "same@example.org"}
        for tenant in ("a", "b"):
            self.import_events(
                [raw],
                dataset=f"scoped-{tenant}",
                collection_scope={
                    "scope_type": "azure.subscription",
                    "scope_id": "same-subscription-text",
                    "tenant_id": tenant,
                },
            )
        events = rows(self.connection, "SELECT event_uid, tenant_id FROM events ORDER BY tenant_id")
        for event in events:
            self.assertTrue(
                evidence(self.connection, event["event_uid"], registry=self.registry)[
                    "source_references"
                ][0]["integrity_verified"]
            )
        # The valid first reference cannot hide a later reference from another tenant,
        # even though both artifact hashes, record pointers, and raw records match.
        self.connection.execute(
            "UPDATE occurrences SET event_uid=? WHERE dataset_id='scoped-b'",
            [events[0]["event_uid"]],
        )
        with self.assertRaisesRegex(ValueError, "artifact manifest collection scope"):
            evidence(self.connection, events[0]["event_uid"], registry=self.registry)

    def test_evidence_checks_stored_manifest_and_pointer(self):
        self.import_events([{"id": "one"}])
        uid = self.connection.execute("SELECT event_uid FROM events").fetchone()[0]
        self.connection.execute("UPDATE occurrences SET record_pointer='missing'")
        with self.assertRaisesRegex(ValueError, "pointer"):
            evidence(self.connection, uid, registry=self.registry)
        self.connection.execute("UPDATE occurrences SET record_pointer='test-record:0'")
        self.connection.execute("UPDATE datasets SET manifest_sha256='tampered'")
        with self.assertRaisesRegex(ValueError, "manifest integrity"):
            evidence(self.connection, uid, registry=self.registry)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "legacy.duckdb"

    def legacy_database(self):
        con = duckdb.connect(str(self.path), config={"enable_external_access": "false"})
        con.execute(LEGACY_SCHEMA)
        return con

    def test_additive_migration_preserves_aws_events_artifacts_and_findings(self):
        con = self.legacy_database()
        content = (ROOT / "fixtures/aws/synthetic/case-01.json").read_bytes()
        raw_events = json.loads(content)["Records"]
        sha = digest(content)
        manifest = {
            "dataset_id": "legacy",
            "provider": "aws",
            "source": "aws.cloudtrail",
            "category": "synthetic",
            "source_urls": ["https://example.org/legacy-test"],
            "license": "MIT",
            "modified": True,
            "limitations": ["Migration test"],
            "files": [{"path": "legacy.json", "sha256": sha, "format": "cloudtrail-json"}],
        }
        con.execute(
            "INSERT INTO datasets VALUES (?, ?, ?)",
            ["legacy", canonical(manifest), digest(canonical(manifest).encode())],
        )
        con.execute("INSERT INTO artifacts VALUES (?, ?)", [sha, content])
        for index, raw in enumerate(raw_events):
            event = normalize(raw)
            for key in ("scope_type", "scope_id", "tenant_id"):
                event.pop(key)
            columns = ",".join(event)
            marks = ",".join("?" for _ in event)
            con.execute(
                f"INSERT INTO events ({columns}) VALUES ({marks}) ON CONFLICT DO NOTHING",
                list(event.values()),
            )
            con.execute(
                "INSERT INTO occurrences VALUES (?, ?, ?, ?, ?)",
                ["legacy", sha, "legacy.json", f"/Records/{index}", event["event_uid"]],
            )
        before = {
            table: rows(con, f"SELECT * FROM {table}")
            for table in ("events", "artifacts", "datasets", "occurrences")
        }
        findings = detect(con)
        con.close()
        migrated = connect(self.path)
        try:
            self.assertEqual(
                migrated.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
                "2",
            )
            for event in rows(migrated, "SELECT * FROM events"):
                self.assertEqual(event.pop("scope_type"), "aws.account")
                self.assertEqual(event.pop("scope_id"), event["account_id"])
                self.assertIsNone(event.pop("tenant_id"))
                self.assertIn(event, before["events"])
                self.assertTrue(
                    evidence(migrated, event["event_uid"])["source_references"][0][
                        "integrity_verified"
                    ]
                )
            for table in ("artifacts", "datasets", "occurrences"):
                self.assertEqual(rows(migrated, f"SELECT * FROM {table}"), before[table])
            self.assertEqual(detect(migrated), findings)
        finally:
            migrated.close()
        reopened = connect(self.path)
        reopened.close()

    def test_failed_migration_rolls_back_all_added_columns_and_version(self):
        con = self.legacy_database()
        # Existing conflicting column forces failure after the first successful ALTER.
        con.execute("ALTER TABLE events ADD COLUMN scope_id VARCHAR")
        con.close()
        with self.assertRaises(duckdb.Error):
            connect(self.path)
        unchanged = duckdb.connect(str(self.path))
        try:
            columns = {
                row[1] for row in unchanged.execute("PRAGMA table_info('events')").fetchall()
            }
            self.assertNotIn("scope_type", columns)
            self.assertNotIn("tenant_id", columns)
            self.assertEqual(unchanged.execute("SELECT value FROM metadata").fetchone()[0], "1")
        finally:
            unchanged.close()

    def test_unsupported_schema_is_rejected_without_mutation(self):
        con = self.legacy_database()
        con.execute("UPDATE metadata SET value='999'")
        before = con.execute("PRAGMA table_info('events')").fetchall()
        con.close()
        with self.assertRaisesRegex(ValueError, "unsupported database schema"):
            connect(self.path)
        unchanged = duckdb.connect(str(self.path))
        try:
            self.assertEqual(unchanged.execute("PRAGMA table_info('events')").fetchall(), before)
            self.assertEqual(unchanged.execute("SELECT value FROM metadata").fetchone()[0], "999")
        finally:
            unchanged.close()


if __name__ == "__main__":
    unittest.main()
