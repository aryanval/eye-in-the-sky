"""Schema-derived Entra parsing, exact evidence and deliberately imperfect evaluation."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from eits.adapters import AdapterRegistry
from eits.adapters.entra import EntraAuditAdapter, EntraSignInAdapter
from eits.db import connect, evidence, ingest, rows
from eits.engine import detect, scoped_sql
from eits.evaluation import evaluate
from eits.model import NormalizationContext, Scope, canonical, digest
from eits.registry import RuleRegistry, resource

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "fixtures/azure/entra-audit/synthetic/manifest.json"
SIGNIN = ROOT / "fixtures/azure/entra-signin/synthetic/manifest.json"
TRUTH = ROOT / "evaluation/entra-ground-truth.json"
SCOPE = json.loads(AUDIT.read_text())["collection_scope"]
RULES = RuleRegistry({"baseline": json.loads(resource("rules/entra.json"))})
ADAPTERS = AdapterRegistry([EntraAuditAdapter(), EntraSignInAdapter()])


def context(source="azure.entra.audit", tenant=None):
    tenant = tenant or SCOPE["scope_id"]
    return NormalizationContext("azure", source, "test", Scope("azure.tenant", tenant, tenant))


def sample():
    return json.loads((AUDIT.parent / "case-01.json").read_text())["value"][:2]


class EntraTests(unittest.TestCase):
    def setUp(self):
        self.con = connect()
        self.addCleanup(self.con.close)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.serial = 0

    def import_records(self, records, tenant=None, source="azure.entra.audit"):
        self.serial += 1
        stem = f"fixture-{self.serial}"
        adapter = ADAPTERS.get("azure", source)
        content = canonical({"value": records}).encode()
        (self.directory / f"{stem}.json").write_bytes(content)
        tenant = tenant or SCOPE["scope_id"]
        manifest = {
            "dataset_id": stem,
            "provider": "azure",
            "source": source,
            "category": "synthetic",
            "collection_scope": {
                "scope_type": "azure.tenant",
                "scope_id": tenant,
                "tenant_id": tenant,
            },
            "license": "MIT",
            "modified": True,
            "source_urls": [
                "https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0"
            ],
            "limitations": ["Synthetic contract test"],
            "files": [
                {"path": f"{stem}.json", "sha256": digest(content), "format": adapter.formats[0]}
            ],
        }
        path = self.directory / f"{stem}-manifest.json"
        path.write_text(canonical(manifest))
        return ingest(self.con, path, registry=ADAPTERS)

    def test_object_and_graph_envelope_exact_resolution(self):
        for adapter, raw in (
            (EntraAuditAdapter(), sample()[0]),
            (EntraSignInAdapter(), {"id": "s", "createdDateTime": None}),
        ):
            for container, pointer in ((raw, ""), ({"value": [raw]}, "/value/0")):
                with self.subTest(source=adapter.source, pointer=pointer):
                    content = canonical(container).encode()
                    self.assertEqual(
                        list(adapter.parse(content, adapter.formats[0])), [(pointer, raw)]
                    )
                    self.assertEqual(adapter.resolve(content, adapter.formats[0], pointer), raw)
                    with self.assertRaises(ValueError):
                        adapter.resolve(content, adapter.formats[0], "/missing")
            for container in ([], {"value": None}, {"value": [1]}):
                with self.assertRaises(ValueError):
                    list(adapter.parse(canonical(container).encode(), adapter.formats[0]))
            with self.assertRaises(ValueError):
                list(adapter.parse(b"{}", "jsonl"))

    def test_audit_normalization_preserves_raw_and_unknown_extensions(self):
        raw = sample()[0]
        raw["futureProperty"] = {"nested": [1, None]}
        original = copy.deepcopy(raw)
        event = EntraAuditAdapter().normalize(raw, context=context())
        self.assertEqual(raw, original)
        self.assertEqual(json.loads(event.raw), raw)
        self.assertEqual(json.loads(event.extensions)["graph"], raw)
        self.assertEqual(event.scope_id, SCOPE["scope_id"])
        self.assertEqual(event.actor_id, raw["initiatedBy"]["user"]["id"])
        self.assertIsNone(event.account_id)
        self.assertIsNone(event.credential_id)
        self.assertEqual(event.outcome, "success")
        self.assertEqual(event.source_ip, "192.0.2.44")

    def test_signin_outcomes_use_integer_error_code_only(self):
        for value, expected in (
            (0, "success"),
            (50126, "failure"),
            (None, "unknown"),
            ("0", "unknown"),
            (False, "unknown"),
            (0.0, "unknown"),
        ):
            with self.subTest(value=value):
                event = EntraSignInAdapter().normalize({"status": {"errorCode": value}})
                self.assertEqual(event.outcome, expected)
                self.assertIsNone(json.loads(event.authentication)["mfa_authenticated"])
        for status in (None, [], {}, {"failureReason": "text only"}):
            self.assertEqual(EntraSignInAdapter().normalize({"status": status}).outcome, "unknown")

    def test_audit_null_missing_ambiguous_initiator_and_result(self):
        adapter = EntraAuditAdapter()
        empty = adapter.normalize({})
        self.assertIsNone(empty.timestamp)
        self.assertIsNone(empty.actor_id)
        self.assertIsNone(empty.scope_id)
        self.assertEqual(empty.action, "unknown")
        self.assertEqual(empty.outcome, "unknown")
        for result, expected in (
            ("success", "success"),
            ("failure", "failure"),
            ("timeout", "unknown"),
            ("unknownFutureValue", "unknown"),
            (None, "unknown"),
        ):
            self.assertEqual(adapter.normalize({"result": result}).outcome, expected)
        raw = {"initiatedBy": {"app": {"appId": "application-id"}}}
        self.assertIsNone(adapter.normalize(raw).actor_id)
        raw["initiatedBy"]["app"]["servicePrincipalId"] = "object-id"
        event = adapter.normalize(raw)
        self.assertEqual((event.actor_id, event.actor_type), ("object-id", "ServicePrincipal"))
        raw["initiatedBy"]["user"] = {"id": "user-id"}
        self.assertIsNone(adapter.normalize(raw).actor_id)

    def test_collection_tenant_is_explicit_not_guest_home_tenant(self):
        raw = {"homeTenantId": "guest-home", "userId": "guest-id"}
        self.assertIsNone(EntraSignInAdapter().normalize(raw).tenant_id)
        event = EntraSignInAdapter().normalize(
            raw, context=context("azure.entra.signin", "resource-tenant")
        )
        self.assertEqual(
            (event.scope_type, event.scope_id, event.tenant_id),
            ("azure.tenant", "resource-tenant", "resource-tenant"),
        )
        for scope in (Scope("azure.tenant", "a", "b"), Scope("azure.subscription", "a", "a")):
            with self.assertRaises(ValueError):
                EntraAuditAdapter().normalize(
                    {}, context=NormalizationContext("azure", "azure.entra.audit", "bad", scope)
                )

    def test_bad_timestamp_and_non_ip_remain_distinct(self):
        for stamp in ("not-a-timestamp", "2025-01-01T00:00:00"):
            with self.assertRaises(ValueError):
                EntraSignInAdapter().normalize({"createdDateTime": stamp})
        event = EntraSignInAdapter().normalize({"ipAddress": "named-address"})
        self.assertEqual(event.source_address, "named-address")
        self.assertIsNone(event.source_ip)
        self.assertIn("source_address_is_not_ip", json.loads(event.quality))

    def test_source_ids_are_scoped_by_collection_tenant_and_source(self):
        raw = sample()[0]
        self.import_records([raw], tenant="tenant-a")
        self.import_records([raw], tenant="tenant-b")
        self.import_records([{"id": raw["id"]}], tenant="tenant-a", source="azure.entra.signin")
        events = rows(self.con, "SELECT event_uid FROM events")
        self.assertEqual(len({event["event_uid"] for event in events}), 3)
        for event in events:
            self.assertTrue(
                evidence(self.con, event["event_uid"], registry=ADAPTERS)["source_references"][0][
                    "integrity_verified"
                ]
            )
        changed = copy.deepcopy(raw)
        changed["result"] = "failure"
        with self.assertRaisesRegex(ValueError, "conflicting payload"):
            self.import_records([changed], tenant="tenant-a")
        self.assertEqual(self.con.execute("SELECT count(*) FROM events").fetchone()[0], 3)

    def test_time_window_boundaries_and_exact_supporting_events(self):
        from datetime import datetime, timedelta

        for seconds, count in ((-1, 0), (0, 0), (1, 1), (1800, 1), (1801, 0)):
            with self.subTest(seconds=seconds):
                first, second = sample()
                first["id"] += str(seconds)
                second["id"] += str(seconds)
                first["initiatedBy"]["user"]["id"] += str(seconds)
                second["initiatedBy"]["user"]["id"] += str(seconds)
                second["activityDateTime"] = (
                    datetime.fromisoformat(first["activityDateTime"].replace("Z", "+00:00"))
                    + timedelta(seconds=seconds)
                ).isoformat()
                before = len(detect(self.con, registry=RULES))
                self.import_records([first, second])
                findings = detect(self.con, registry=RULES)
                self.assertEqual(len(findings) - before, count)
                if count:
                    pair = [
                        EntraAuditAdapter().normalize(raw, context=context()).event_uid
                        for raw in (first, second)
                    ]
                    finding = next(item for item in findings if item["event_uids"] == pair)
                    self.assertEqual(finding["source_event_ids"], [first["id"], second["id"]])

    def test_submicrosecond_detection_and_hunt_boundaries(self):
        cases = (
            ("12:00:00.0000001Z", "12:00:00.0000002Z", 1),
            ("12:00:00.0000001Z", "12:00:00.0000001Z", 0),
            ("12:00:00.0000001Z", "12:00:00.0000000Z", 0),
            ("12:00:00.0000001Z", "12:30:00.0000001Z", 1),
            ("12:00:00.0000001Z", "12:30:00.0000002Z", 0),
            ("12:00:00.0000001Z", "12:30:00.0000000Z", 1),
        )
        for index, (start, end, expected) in enumerate(cases):
            with self.subTest(start=start, end=end):
                first, second = sample()
                first["activityDateTime"] = "2025-04-01T" + start
                second["activityDateTime"] = "2025-04-01T" + end
                before = len(detect(self.con, registry=RULES))
                self.import_records([first, second], tenant=f"fractional-{index}")
                self.assertEqual(len(detect(self.con, registry=RULES)) - before, expected)
                self.assertEqual(
                    json.loads(EntraAuditAdapter().normalize(first).extensions)[
                        "timestamp_submicrosecond_ns"
                    ],
                    100,
                )
        signins = [
            {"id": str(index), "userId": "user", "createdDateTime": "2025-04-01T" + stamp}
            for index, stamp in enumerate(
                ("12:00:00.0000001Z", "13:00:00.0000001Z", "13:00:00.0000002Z")
            )
        ]
        self.import_records(signins, source="azure.entra.signin")
        leads = rows(
            self.con, scoped_sql(resource("sql/HUNT-002.sql")), ["azure", "azure.entra.signin", 1]
        )
        self.assertEqual(leads[0]["signins"], 2)
        for adapter, field in (
            (EntraAuditAdapter(), "activityDateTime"),
            (EntraSignInAdapter(), "createdDateTime"),
        ):
            with self.assertRaises(ValueError):
                adapter.normalize({field: "2025-04-01T12:00:00.0000000001Z"})

    def test_nonstrings_cannot_establish_target_object_identity(self):
        first, second = sample()
        first["targetResources"][0]["id"] = 123
        second["targetResources"][0]["id"] = 123
        self.import_records([first, second])
        self.assertEqual(detect(self.con, registry=RULES), [])

    def test_equal_names_ip_and_object_ids_cannot_join_across_tenants(self):
        first, second = sample()
        self.import_records([first], tenant="tenant-a")
        self.import_records([second], tenant="tenant-b")
        self.assertEqual(detect(self.con, registry=RULES), [])
        self.import_records([second], tenant="tenant-a")
        self.assertEqual(len(detect(self.con, registry=RULES)), 1)

    def test_multi_target_arrays_match_exact_id_without_target_position(self):
        first, second = sample()
        second["targetResources"].insert(0, {"id": "different", "type": "ServicePrincipal"})
        second["targetResources"].append(copy.deepcopy(second["targetResources"][1]))
        self.import_records([first, second])
        findings = detect(self.con, registry=RULES)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0]["event_uids"]), 2)

    def test_evaluation_retains_false_positives_misses_and_ambiguity(self):
        report = evaluate(AUDIT, TRUTH, registry=RULES, adapter_registry=ADAPTERS)
        metrics = report["rules"]["EITS-ENTRA-001"]["metrics"]
        self.assertEqual(
            {key: metrics[key] for key in ("tp", "fp", "fn", "tn")},
            {"tp": 3, "fp": 2, "fn": 6, "tn": 5},
        )
        self.assertEqual(metrics["precision"], 0.6)
        self.assertEqual(metrics["recall"], 0.333333)
        self.assertEqual(metrics["complete_telemetry_recall"], 0.75)
        self.assertEqual((metrics["ambiguous"], metrics["ambiguous_alerted"]), (2, 1))
        self.assertEqual(report["evidence_events_verified"], 12)
        self.assertEqual(report["rules"]["EITS-ENTRA-001"]["unexpected_findings"], [])

    def test_hunt_preserves_unknowns_and_exact_evidence(self):
        ingest(self.con, SIGNIN, registry=ADAPTERS)
        leads = rows(
            self.con, scoped_sql(resource("sql/HUNT-002.sql")), ["azure", "azure.entra.signin", 24]
        )
        self.assertEqual(len(leads), 5)
        self.assertEqual(sum(lead["signins"] for lead in leads), 13)
        unknown = [lead for lead in leads if lead["actor_id"] is None]
        self.assertEqual(len(unknown), 2)
        self.assertTrue(all(lead["signins"] == 1 for lead in unknown))
        self.assertEqual(sum(lead["unknown_outcomes"] for lead in leads), 1)
        self.assertEqual(sum(lead["elevated_risk_observations"] for lead in leads), 1)
        self.assertEqual(sum(lead["mfa_outcome_unknown"] for lead in leads), 13)
        for lead in leads:
            self.assertNotIn("severity", lead)
            for uid in lead["event_uids"]:
                self.assertTrue(
                    evidence(self.con, uid, registry=ADAPTERS)["source_references"][0][
                        "integrity_verified"
                    ]
                )
        short = rows(
            self.con,
            scoped_sql(resource("sql/HUNT-002.sql")),
            ["azure", "azure.entra.signin", 0.01],
        )
        self.assertLess(sum(lead["signins"] for lead in short), 13)
        self.assertEqual(sum(lead["unknown_outcomes"] for lead in short), 1)

    def test_original_presentation_excerpts_are_hash_verified_not_repaired(self):
        for source in ("entra-signin", "entra-audit"):
            directory = ROOT / "fixtures/azure" / source / "documentation"
            provenance = json.loads((directory / "provenance.json").read_text())
            content = (directory / provenance["file"]).read_bytes()
            self.assertEqual(digest(content), provenance["sha256"])
            self.assertFalse(provenance["modified"])
            body = content.split(b"\n\n", 1)[1]
            if source == "entra-signin":
                with self.assertRaises(json.JSONDecodeError):
                    json.loads(body)
            else:
                self.assertIn("Type", json.loads(body)["value"][0]["targetResources"][0])


if __name__ == "__main__":
    unittest.main()
