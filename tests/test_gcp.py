"""GCP parser, native semantics, exact evidence and deliberately imperfect evaluation."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from eits.adapters import AdapterRegistry
from eits.adapters.gcp import GcpAuditAdapter
from eits.db import connect, evidence, ingest, rows
from eits.engine import detect, explain, scoped_sql
from eits.evaluation import score
from eits.model import canonical, digest
from eits.registry import RuleRegistry, resource
from scripts.generate_gcp import bucket_change, entry, generate, key_pair

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "fixtures/gcp/synthetic/manifest.json"
TRUTH = ROOT / "evaluation/gcp-ground-truth.json"


class GcpTests(unittest.TestCase):
    def setUp(self):
        self.adapter = GcpAuditAdapter()
        self.adapters = AdapterRegistry([self.adapter])
        self.rules = RuleRegistry({"baseline": json.loads(resource("rules/gcp.json"))})
        self.connection = connect()
        self.addCleanup(self.connection.close)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.counter = 0

    def import_records(self, records):
        self.counter += 1
        directory = Path(self.directory.name) / str(self.counter)
        directory.mkdir()
        content = json.dumps({"entries": records}).encode()
        (directory / "events.json").write_bytes(content)
        manifest = {
            "dataset_id": f"gcp-test-{self.counter}",
            "provider": "gcp",
            "source": "gcp.audit",
            "category": "synthetic",
            "source_urls": [
                "https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry"
            ],
            "license": "LicenseRef-Proprietary",
            "modified": True,
            "limitations": ["Test-only synthetic input"],
            "files": [
                {"path": "events.json", "sha256": digest(content), "format": "gcp-audit-json"}
            ],
        }
        path = directory / "manifest.json"
        path.write_text(json.dumps(manifest))
        return ingest(self.connection, path, registry=self.adapters)

    def findings(self):
        return detect(self.connection, registry=self.rules)

    def hunt(self, hours=24):
        return rows(
            self.connection, scoped_sql(resource("sql/HUNT-003.sql")), ["gcp", "gcp.audit", hours]
        )

    def test_supported_envelopes_and_exact_record_pointers(self):
        raw = entry(1, "example", "iam.googleapis.com", "GetIamPolicy")
        for envelope, pointer in ((raw, ""), ([raw], "/0"), ({"entries": [raw]}, "/entries/0")):
            with self.subTest(pointer=pointer):
                content = json.dumps(envelope).encode()
                self.assertEqual(
                    list(self.adapter.parse(content, "gcp-audit-json")), [(pointer, raw)]
                )
                self.assertEqual(self.adapter.resolve(content, "gcp-audit-json", pointer), raw)
                with self.assertRaisesRegex(ValueError, "pointer"):
                    self.adapter.resolve(content, "gcp-audit-json", "wrong")
        for envelope in (None, 7, {"entries": None}, {"entries": {}}):
            with self.assertRaises(ValueError):
                list(self.adapter.parse(json.dumps(envelope).encode(), "gcp-audit-json"))
        with self.assertRaisesRegex(ValueError, "format"):
            list(self.adapter.parse(b"{}", "jsonl"))

    def test_defensible_mapping_and_raw_retention(self):
        raw, _ = key_pair(1)
        before = copy.deepcopy(raw)
        event = self.adapter.normalize(raw)
        self.assertEqual(raw, before)
        self.assertEqual(json.loads(event.raw), before)
        self.assertEqual(event.scope_type, "gcp.project")
        self.assertEqual(event.scope_id, "eits-lab-001")
        self.assertIsNone(event.account_id)
        self.assertIsNone(event.tenant_id)
        self.assertIsNone(event.region)
        self.assertIsNone(event.actor_type)
        self.assertIsNone(event.actor_arn)
        self.assertEqual(
            event.actor_id, raw["protoPayload"]["authenticationInfo"]["principalSubject"]
        )
        self.assertEqual(json.loads(event.source_event_id), [raw["insertId"], raw["timestamp"]])
        self.assertEqual(json.loads(event.extensions)["protoPayload"], raw["protoPayload"])
        event.validate(
            provider="gcp",
            source="gcp.audit",
            raw=raw,
            scope_types=("gcp.project",),
            has_tenant=False,
        )

    def test_missing_null_fields_and_ip_redaction_remain_unknown(self):
        raw = {
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "iam.googleapis.com",
                "methodName": "GetIamPolicy",
            }
        }
        for nulls in (False, True):
            value = copy.deepcopy(raw)
            if nulls:
                value.update(timestamp=None, insertId=None, logName=None, resource=None)
                value["protoPayload"].update(
                    status=None, authenticationInfo=None, requestMetadata=None
                )
            event = self.adapter.normalize(value)
            self.assertEqual(event.outcome, "unknown")
            for field in (
                "source_event_id",
                "timestamp",
                "scope_type",
                "scope_id",
                "actor_id",
                "credential_id",
                "source_ip",
                "source_address",
            ):
                self.assertIsNone(getattr(event, field), field)
        raw["protoPayload"]["authenticationInfo"] = {
            "principalEmail": "looks-like-user@example.invalid"
        }
        raw["protoPayload"]["requestMetadata"] = {"callerIp": "private"}
        event = self.adapter.normalize(raw)
        self.assertIsNone(event.actor_id)
        self.assertEqual(event.source_address, "private")
        self.assertIsNone(event.source_ip)

    def test_outcome_and_operation_completion(self):
        for status, expected in (
            ({}, "success"),
            ({"code": 0}, "success"),
            ({"code": 7}, "failure"),
            (None, "unknown"),
            ({"code": "0"}, "unknown"),
            ({"code": False}, "unknown"),
        ):
            raw = entry(1, "status", "iam.googleapis.com", "GetIamPolicy")
            raw["protoPayload"]["status"] = status
            self.assertEqual(self.adapter.normalize(raw).outcome, expected)
        raw["protoPayload"]["status"] = {}
        raw["operation"] = {"id": "operation", "first": True}
        self.assertEqual(self.adapter.normalize(raw).outcome, "unknown")
        raw["operation"]["last"] = True
        self.assertEqual(self.adapter.normalize(raw).outcome, "success")

    def test_invalid_typed_payload_fields_and_timestamp_rejected(self):
        for raw in (None, [], {}, {"jsonPayload": {}}, {"protoPayload": {"@type": "different"}}):
            with self.assertRaises(ValueError):
                self.adapter.normalize(raw)
        for field in ("serviceName", "methodName"):
            raw = entry(1, "invalid", "iam.googleapis.com", "GetIamPolicy")
            raw["protoPayload"][field] = None
            with self.assertRaisesRegex(ValueError, "requires"):
                self.adapter.normalize(raw)
        for stamp in (
            "bad-date",
            "2025-04-05T12:00:00",
            "2025-04-05T12:00:00.1234567891Z",
            "2025-04-05T12:00:00,000000101Z",
            "2025-04-05T12:00:00,1234567891Z",
            "2025-04-05T12:00:00.000000101+00:00:00",
        ):
            raw = entry(1, "invalid", "iam.googleapis.com", "GetIamPolicy")
            raw["timestamp"] = stamp
            with self.assertRaises(ValueError):
                self.adapter.normalize(raw)

    def test_scope_is_log_owner_and_does_not_guess_from_resource(self):
        raw = entry(1, "scope", "iam.googleapis.com", "GetIamPolicy")
        for prefix, expected in (
            ("projects", "gcp.project"),
            ("folders", "gcp.folder"),
            ("organizations", "gcp.organization"),
        ):
            raw["logName"] = f"{prefix}/same-id/logs/cloudaudit.googleapis.com%2Factivity"
            event = self.adapter.normalize(raw)
            self.assertEqual((event.scope_type, event.scope_id), (expected, "same-id"))
            self.assertIsNone(event.tenant_id)
        for log_name in (
            None,
            "billingAccounts/billing/logs/cloudaudit.googleapis.com%2Factivity",
            "projects//logs/activity",
        ):
            raw["logName"] = log_name
            event = self.adapter.normalize(raw)
            self.assertIsNone(event.scope_id)
            self.assertIn("missing_scope", json.loads(event.quality))

    def test_source_identity_conflicts_use_timestamp_and_provider_scope(self):
        raw = entry(1, "same", "iam.googleapis.com", "GetIamPolicy")
        self.import_records([raw])
        altered = copy.deepcopy(raw)
        altered["protoPayload"]["methodName"] = "SetIamPolicy"
        with self.assertRaisesRegex(ValueError, "conflicting payload"):
            self.import_records([altered])
        self.assertEqual(self.connection.execute("SELECT count(*) FROM events").fetchone()[0], 1)
        later = copy.deepcopy(raw)
        later["timestamp"] = "2025-04-05T12:00:01Z"
        other_project = copy.deepcopy(raw)
        other_project["logName"] = other_project["logName"].replace("eits-lab-001", "other-project")
        other_kind = copy.deepcopy(raw)
        other_kind["logName"] = other_kind["logName"].replace("projects/", "folders/")
        self.import_records([later, other_project, other_kind])
        self.assertEqual(self.connection.execute("SELECT count(*) FROM events").fetchone()[0], 4)

    def test_nanosecond_order_and_inclusive_window(self):
        cases = [
            ("12:00:00.000000101", True),
            ("12:00:00.000000100", False),
            ("12:00:00.000000099", False),
            ("12:30:00.000000100", True),
            ("12:30:00.000000101", False),
            ("12:29:59.999999999", True),
        ]
        expected = 0
        for number, (end, triggers) in enumerate(cases, 200):
            a, b = key_pair(number)
            a["timestamp"] = "2025-04-05T12:00:00.000000100Z"
            b["timestamp"] = f"2025-04-05T{end}Z"
            self.import_records([a, b])
            expected += triggers
        self.assertEqual(len(self.findings()), expected)
        self.assertTrue(
            all(item["predicate_evidence"][0]["elapsed_seconds"] > 0 for item in self.findings())
        )

    def test_pair_isolation_and_missing_attribution(self):
        variants = (
            "other_project",
            "other_key",
            "email_only",
            "missing_creation_name",
            "unknown_status",
            "failed_use",
        )
        for number, variant in enumerate(variants, 220):
            a, b = key_pair(number)
            if variant == "other_project":
                b["logName"] = b["logName"].replace(f"eits-lab-{number:03d}", "different")
            elif variant == "other_key":
                b["protoPayload"]["authenticationInfo"]["serviceAccountKeyName"] += "other"
            elif variant == "email_only":
                b["protoPayload"]["authenticationInfo"].pop("serviceAccountKeyName")
            elif variant == "missing_creation_name":
                a["protoPayload"]["response"]["name"] = None
            elif variant == "unknown_status":
                b["protoPayload"]["status"] = None
            else:
                b["protoPayload"]["status"] = {"code": 7}
            self.import_records([a, b])
        self.assertEqual(self.findings(), [])

    def test_single_event_keeps_all_matching_delta_evidence(self):
        value = bucket_change(301)
        value["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"].append(
            {
                "action": "ADD",
                "member": "allAuthenticatedUsers",
                "role": "roles/storage.objectAdmin",
            }
        )
        self.import_records([value])
        finding = self.findings()[0]
        self.assertEqual(len(finding["event_uids"]), 1)
        self.assertEqual(len(finding["predicate_evidence"]), 2)
        details = explain(
            self.connection,
            finding["finding_id"],
            registry=self.rules,
            adapter_registry=self.adapters,
        )
        self.assertEqual(details["events"][0]["raw"], value)
        self.assertTrue(details["events"][0]["source_references"][0]["integrity_verified"])

    def test_bucket_predicates_cannot_join_different_deltas(self):
        value = bucket_change(302)
        deltas = value["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"]
        deltas[0]["action"] = "REMOVE"
        deltas.append(
            {
                "action": "ADD",
                "member": "user:reader@example.invalid",
                "role": "roles/storage.objectViewer",
            }
        )
        self.import_records([value])
        self.assertEqual(self.findings(), [])

    def test_rule_engine_excludes_other_provider_and_source(self):
        a, b = key_pair(303)
        self.import_records([a, b])
        self.assertEqual(len(self.findings()), 1)
        self.connection.execute(
            "UPDATE events SET source='aws.cloudtrail' WHERE action='SetIamPolicy'"
        )
        self.assertEqual(self.findings(), [])
        self.connection.execute(
            "UPDATE events SET source='gcp.audit', provider='azure' WHERE action='SetIamPolicy'"
        )
        self.assertEqual(self.findings(), [])

    def test_hunt_keeps_unknown_unused_and_unresolvable_creations(self):
        ingest(self.connection, MANIFEST, registry=self.adapters)
        leads = self.hunt()
        self.assertEqual(len(leads), 14)
        self.assertEqual(
            {lead["observation"] for lead in leads},
            {"use_observed", "no_use_observed", "unresolvable"},
        )
        for lead in leads:
            self.assertNotIn("severity", lead)
            self.assertNotIn("finding_id", lead)
            for uid in [lead["creation_uid"], *lead["use_event_uids"]]:
                self.assertTrue(
                    evidence(self.connection, uid, registry=self.adapters)["source_references"][0][
                        "integrity_verified"
                    ]
                )
        delayed = self.adapter.normalize(key_pair(6)[0]).event_uid
        self.assertEqual(
            next(lead for lead in leads if lead["creation_uid"] == delayed)["event_count"], 1
        )
        a, b = key_pair(320)
        a["protoPayload"].pop("status")
        self.import_records([a, b])
        self.assertEqual(
            next(
                lead
                for lead in self.hunt()
                if lead["creation_uid"] == self.adapter.normalize(a).event_uid
            )["creation_outcome"],
            "unknown",
        )

    def test_hunt_nanosecond_window_boundary(self):
        for number, nanos in ((330, 100), (331, 101)):
            a, b = key_pair(number)
            a["timestamp"] = "2025-04-05T12:00:00.000000100Z"
            b["timestamp"] = f"2025-04-05T13:00:00.{nanos:09d}Z"
            self.import_records([a, b])
        self.assertEqual(sorted(lead["event_count"] for lead in self.hunt(1)), [0, 1])

    def test_corpus_metrics_ambiguous_separation_and_exact_evidence(self):
        result = ingest(self.connection, MANIFEST, registry=self.adapters)
        self.assertEqual(result["new_events"], 73)
        findings = self.findings()
        self.assertEqual(len(findings), 9)
        scenarios = json.loads(TRUTH.read_text())["scenarios"]
        results = score(findings, scenarios, registry=self.rules)
        expected = {
            "EITS-GCP-001": (2, 1, 6, 5, 0.666667, 0.25, 0.4),
            "EITS-GCP-002": (2, 2, 5, 5, 0.5, 0.285714, 0.666667),
        }
        for rule, counts in expected.items():
            metrics = results[rule]["metrics"]
            self.assertEqual(
                tuple(
                    metrics[key]
                    for key in (
                        "tp",
                        "fp",
                        "fn",
                        "tn",
                        "precision",
                        "recall",
                        "complete_telemetry_recall",
                    )
                ),
                counts,
            )
            self.assertEqual((metrics["ambiguous"], metrics["ambiguous_alerted"]), (1, 1))
            self.assertEqual(results[rule]["unexpected_findings"], [])
        for finding in findings:
            resolved = explain(
                self.connection,
                finding["finding_id"],
                registry=self.rules,
                adapter_registry=self.adapters,
            )
            self.assertTrue(resolved["sql_sha256"])
            self.assertTrue(resolved["observed"])
            self.assertTrue(resolved["inferred"])
            self.assertTrue(resolved["unresolved"])
            for event in resolved["events"]:
                self.assertTrue(
                    all(ref["integrity_verified"] for ref in event["source_references"])
                )
        wrong = copy.deepcopy(findings)
        true_positive = next(
            item for item in results["EITS-GCP-001"]["scenarios"] if item["result"] == "tp"
        )
        paired = next(
            item for item in wrong if item["finding_id"] == true_positive["finding_ids"][0]
        )
        paired["event_uids"] = paired["event_uids"][:1]
        damaged = score(wrong, scenarios, registry=self.rules)
        self.assertEqual(damaged["EITS-GCP-001"]["metrics"]["tp"], 1)
        self.assertEqual(damaged["EITS-GCP-001"]["metrics"]["fn"], 7)
        self.assertEqual(damaged["EITS-GCP-001"]["metrics"]["fp"], 2)

    def test_documentation_excerpts_are_unmodified_and_not_official_fixtures(self):
        directory = ROOT / "fixtures/gcp/documentation"
        provenance = json.loads((directory / "provenance.json").read_text())
        for item in provenance["files"]:
            self.assertEqual(digest((directory / item["path"]).read_bytes()), item["sha256"])
            self.assertFalse(item["ingestable_dataset"])
        raw = json.loads((directory / "project-role-grant-excerpt.json").read_text())
        event = self.adapter.normalize(raw)
        self.assertIsNone(event.timestamp)
        self.assertIsNone(event.source_event_id)
        self.assertEqual(event.outcome, "unknown")
        self.assertEqual(json.loads(event.raw), raw)
        with self.assertRaises(json.JSONDecodeError):
            list(
                self.adapter.parse(
                    (directory / "key-creation-excerpt.txt").read_bytes(), "gcp-audit-json"
                )
            )
        self.assertFalse((ROOT / "fixtures/gcp/official/manifest.json").exists())

    def test_generator_is_deterministic_and_labels_are_separate(self):
        root = Path(self.directory.name)
        (root / "evaluation").mkdir()
        with patch("scripts.generate_gcp.ROOT", root):
            generate()
        self.assertEqual(
            (root / "evaluation/gcp-ground-truth.json").read_bytes(), TRUTH.read_bytes()
        )
        for path in (root / "fixtures/gcp/synthetic").iterdir():
            self.assertEqual(path.read_bytes(), (MANIFEST.parent / path.name).read_bytes())
            if path.name != "manifest.json":
                for raw in json.loads(path.read_bytes())["entries"]:
                    text = canonical(raw)
                    self.assertNotIn("telemetry_complete", text)
                    self.assertNotIn("scenario_id", text)
                    self.assertNotIn("anchor_event_uids", text)


if __name__ == "__main__":
    unittest.main()
