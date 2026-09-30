"""REST EventData mappings, exact evidence, isolation and imperfect scenario scoring."""

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eits.adapters import AdapterRegistry
from eits.adapters.aws import CloudTrailAdapter
from eits.adapters.azure_activity import ACTOR_TENANT, OBJECT_ID, AzureActivityAdapter
from eits.db import connect, evidence, ingest, rows
from eits.engine import detect, explain
from eits.evaluation import score
from eits.model import NormalizationContext, Scope, canonical, digest
from eits.registry import RuleRegistry

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/azure/activity"
ADAPTER = AzureActivityAdapter()
ADAPTERS = AdapterRegistry([ADAPTER, CloudTrailAdapter()])
RULES = RuleRegistry(
    {"baseline": json.loads((ROOT / "src/eits/rules/azure-activity.json").read_text())}
)


def source_case(number=1):
    return json.loads((FIXTURES / f"synthetic/case-{number:02d}.json").read_text())["value"]


def manifest(directory, records, name="test", collection_scope=None):
    path = directory / f"{name}.json"
    path.write_text(canonical({"value": records}))
    value = {
        "dataset_id": name,
        "provider": "azure",
        "source": "azure.activity",
        "category": "synthetic",
        "source_urls": ["https://learn.microsoft.com/en-us/rest/api/monitor/activity-logs/list"],
        "license": "MIT",
        "modified": False,
        "limitations": ["Synthetic parser test"],
        "files": [
            {"path": path.name, "sha256": digest(path.read_bytes()), "format": ADAPTER.formats[0]}
        ],
    }
    if collection_scope is not None:
        value["collection_scope"] = collection_scope
    output = directory / f"{name}-manifest.json"
    output.write_text(canonical(value))
    return output


class AzureActivityTests(unittest.TestCase):
    def setUp(self):
        self.connection = connect()
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)

    def tearDown(self):
        self.connection.close()
        self.temp.cleanup()

    def load(self, records, name="test", collection_scope=None):
        return ingest(
            self.connection,
            manifest(self.directory, records, name, collection_scope),
            registry=ADAPTERS,
        )

    def findings(self):
        return detect(self.connection, registry=RULES)

    def test_official_example_is_exact_extraction_and_evidence(self):
        vendor = (FIXTURES / "official/GetActivityLogsFiltered.source.json").read_bytes()
        content = (FIXTURES / "official/sample-01.json").read_bytes()
        self.assertIn(content, vendor)
        original = json.loads(vendor)["responses"]["200"]["body"]
        self.assertEqual(json.loads(content), original)
        ingest(self.connection, FIXTURES / "official/manifest.json", registry=ADAPTERS)
        event = rows(self.connection, "SELECT * FROM events")[0]
        self.assertEqual(event["source_event_id"], "44ade6b4-3813-45e6-ae27-7420a95fa2f8")
        self.assertEqual(event["outcome"], "success")
        self.assertEqual(event["actor_id"], "2468adf0-8211-44e3-95xq-85137af64708")
        self.assertIsNone(event["tenant_id"])
        self.assertIsNone(event["account_id"])
        self.assertEqual(json.loads(event["raw"]), original["value"][0])
        retained = evidence(self.connection, event["event_uid"], registry=ADAPTERS)
        self.assertEqual(retained["raw"], original["value"][0])
        self.assertEqual(retained["source_references"][0]["record_pointer"], "/value/0")

    def test_missing_and_null_are_unknown(self):
        raw = {
            "operationName": {"value": "Microsoft.Support/supportTickets/write"},
            "status": None,
            "claims": None,
            "tenantId": None,
            "properties": None,
        }
        event = ADAPTER.normalize(raw)
        for key in (
            "timestamp",
            "actor_id",
            "actor_type",
            "scope_id",
            "tenant_id",
            "credential_id",
            "account_id",
            "source_event_id",
            "source_ip",
        ):
            self.assertIsNone(getattr(event, key), key)
        self.assertEqual(event.outcome, "unknown")
        self.assertEqual(json.loads(event.extensions)["properties"], None)
        self.assertEqual(json.loads(event.authentication)["claims"], None)
        self.assertEqual(json.loads(event.raw), raw)
        for status in ("Started", "In progress", "Resolved", "Accepted", None):
            raw["status"] = {"value": status}
            self.assertEqual(ADAPTER.normalize(raw).outcome, "unknown")

    def test_collection_scope_is_explicit_and_token_tenant_is_not_resource_tenant(self):
        raw = source_case()[0]
        raw.pop("tenantId")
        raw.pop("subscriptionId")
        self.assertIsNone(ADAPTER.normalize(raw).tenant_id)
        scope = Scope("azure.subscription", "subscription-context", "resource-tenant-context")
        context = NormalizationContext("azure", "azure.activity", "test", scope)
        event = ADAPTER.normalize(raw, context=context)
        self.assertEqual(event.scope_id, "subscription-context")
        self.assertEqual(event.tenant_id, "resource-tenant-context")
        self.assertEqual(
            json.loads(event.extensions)["actor_tenant_id"], raw["claims"][ACTOR_TENANT]
        )
        self.assertNotEqual(event.event_uid, ADAPTER.normalize(raw).event_uid)
        raw["tenantId"] = "different-resource-tenant"
        with self.assertRaisesRegex(ValueError, "tenant differs"):
            ADAPTER.normalize(raw, context=context)

    def test_collection_scope_conflict_rolls_back(self):
        with self.assertRaisesRegex(ValueError, "subscription differs"):
            self.load(
                source_case(),
                collection_scope={"scope_type": "azure.subscription", "scope_id": "wrong"},
            )
        self.assertEqual(rows(self.connection, "SELECT count(*) AS n FROM events")[0]["n"], 0)

    def test_unsupported_shapes_bad_times_and_pointers_rejected(self):
        for raw in (
            {"records": source_case()},
            {"operationName": "Microsoft.Insights/diagnosticSettings/delete"},
            {"operationName": {"localizedValue": "Delete"}},
        ):
            with self.assertRaises(ValueError):
                ADAPTER.normalize(raw)
        for value in ([], {"value": None}, {"value": [None]}):
            with self.assertRaises(ValueError):
                list(ADAPTER.parse(canonical(value).encode(), ADAPTER.formats[0]))
        raw = source_case()[0]
        for stamp in ("2026-01-01T00:00:00", "bad-date"):
            raw["eventTimestamp"] = stamp
            with self.assertRaises(ValueError):
                ADAPTER.normalize(raw)
        with self.assertRaises(ValueError):
            ADAPTER.resolve(
                canonical({"value": source_case()}).encode(), ADAPTER.formats[0], "/value/999"
            )

    def test_source_event_id_conflict_and_scope_isolation(self):
        raw = source_case()[0]
        self.load([raw], "original")
        changed = copy.deepcopy(raw)
        changed["status"] = {"value": "Failed"}
        with self.assertRaisesRegex(ValueError, "conflict"):
            self.load([changed], "conflicting")
        changed["subscriptionId"] = "other-subscription"
        self.load([changed], "other-subscription")
        changed["tenantId"] = "other-tenant"
        self.load([changed], "other-tenant")
        self.assertEqual(rows(self.connection, "SELECT count(*) AS n FROM events")[0]["n"], 3)

    def test_domain_separation_and_no_email_or_ip_identity_fallback(self):
        start, end = source_case()[:2]
        self.assertEqual(start["caller"], end["caller"])
        end["claims"].pop(OBJECT_ID)
        self.load([start, end])
        self.assertEqual(self.findings(), [])
        self.assertTrue(ADAPTER.normalize(start).event_uid.startswith("evt_v2_"))
        self.assertNotEqual(
            ADAPTER.normalize(start).event_uid,
            CloudTrailAdapter()
            .normalize(
                {
                    "eventID": start["eventDataId"],
                    "eventSource": "test.amazonaws.com",
                    "eventName": "Test",
                }
            )
            .event_uid,
        )

    def test_time_window_edges(self):
        base = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        for offset, expected in ((-1, 0), (0, 0), (0.000001, 1), (1800, 1), (1800.000001, 0)):
            with self.subTest(offset=offset):
                connection = connect()
                try:
                    start, end = source_case()[:2]
                    end["eventTimestamp"] = (base + timedelta(seconds=offset)).isoformat()
                    ingest(
                        connection,
                        manifest(self.directory, [start, end], f"window-{offset}"),
                        registry=ADAPTERS,
                    )
                    self.assertEqual(len(detect(connection, registry=RULES)), expected)
                finally:
                    connection.close()

    def test_actor_resource_tenant_subscription_and_provider_isolation(self):
        for field in ("scope", "tenant", "actor", "actor_tenant"):
            with self.subTest(field=field):
                connection = connect()
                start, end = source_case()[:2]
                if field == "scope":
                    end["subscriptionId"] = "different"
                elif field == "tenant":
                    end["tenantId"] = "different"
                else:
                    end["claims"][OBJECT_ID if field == "actor" else ACTOR_TENANT] = "different"
                try:
                    ingest(
                        connection, manifest(self.directory, [start, end], field), registry=ADAPTERS
                    )
                    self.assertEqual(detect(connection, registry=RULES), [])
                finally:
                    connection.close()
        self.load(source_case())
        self.connection.execute(
            "UPDATE events SET provider='aws' WHERE action=?",
            [source_case()[1]["operationName"]["value"]],
        )
        self.assertEqual(self.findings(), [])

    def test_submicrosecond_boundaries_retain_source_precision(self):
        cases = (
            ("12:00:00.0000001Z", "12:00:00.0000002Z", 1),
            ("12:00:00.0000001Z", "12:00:00.0000001Z", 0),
            ("12:00:00.0000001Z", "12:00:00.0000000Z", 0),
            ("12:00:00.0000001Z", "12:30:00.0000001Z", 1),
            ("12:00:00.0000001Z", "12:30:00.0000002Z", 0),
            ("12:00:00.0000001Z", "12:30:00.0000000Z", 1),
        )
        for index, (start_time, end_time, expected) in enumerate(cases):
            with self.subTest(start=start_time, end=end_time):
                connection = connect()
                start, end = source_case()[:2]
                start["eventTimestamp"] = "2026-01-01T" + start_time
                end["eventTimestamp"] = "2026-01-01T" + end_time
                try:
                    ingest(
                        connection,
                        manifest(self.directory, [start, end], f"precision-{index}"),
                        registry=ADAPTERS,
                    )
                    self.assertEqual(len(detect(connection, registry=RULES)), expected)
                    self.assertEqual(
                        json.loads(ADAPTER.normalize(start).extensions)[
                            "timestamp_submicrosecond_ns"
                        ],
                        100,
                    )
                finally:
                    connection.close()

    def test_synthetic_scoring_exact_evidence_and_counterevidence(self):
        ingest(self.connection, FIXTURES / "synthetic/manifest.json", registry=ADAPTERS)
        scenarios = json.loads((ROOT / "evaluation/azure-activity-ground-truth.json").read_text())[
            "scenarios"
        ]
        findings = self.findings()
        report = score(findings, scenarios, registry=RULES)["EITS-AZURE-001"]
        metrics = report["metrics"]
        self.assertEqual(
            {key: metrics[key] for key in ("tp", "fp", "fn", "tn", "ambiguous_alerted")},
            {"tp": 2, "fp": 2, "fn": 7, "tn": 5, "ambiguous_alerted": 1},
        )
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["recall"], 0.222222)
        self.assertEqual(metrics["complete_telemetry_recall"], 0.4)
        for finding in findings:
            self.assertEqual(len(finding["event_uids"]), 2)
            explained = explain(
                self.connection, finding["finding_id"], registry=RULES, adapter_registry=ADAPTERS
            )
            self.assertEqual(len(explained["events"]), 2)
            for event in explained["events"]:
                self.assertTrue(event["source_references"])
                self.assertEqual(event["raw"]["eventDataId"], event["source_event_id"])
            self.assertTrue(explained["sql_sha256"])
            self.assertTrue(explained["observed"])
            self.assertTrue(explained["inferred"])
            self.assertTrue(explained["unresolved"])


if __name__ == "__main__":
    unittest.main()
