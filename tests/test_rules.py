"""Generic engine contracts, using test queries rather than new security rules."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from test_adapters import StubAdapter, write_manifest

from eits.adapters import AdapterRegistry
from eits.db import connect, ingest, rows
from eits.engine import catalog, detect, explain, hunt, revisions, rule_sql
from eits.evaluation import evaluate, package_hashes, score
from eits.model import canonical, digest
from eits.registry import RuleRegistry

ROOT = Path(__file__).resolve().parents[1]


def test_registry(
    sql, *, contract=None, provider="aws", source="aws.cloudtrail", rule_id="TEST-001"
):
    metadata = {
        "version": "test-1",
        "title": "Engine contract test",
        "severity": "informational",
        "provider": provider,
        "source": source,
        "sql_path": "test.sql",
        "evidence": contract or {"list_column": "support"},
        "attack": [],
        "observed": "Supporting test rows exist.",
        "inferred": "No security inference.",
        "cannot_establish": ["Any security outcome"],
    }
    return RuleRegistry(
        {"baseline": {rule_id: metadata}}, resource_loader={"test.sql": sql}.__getitem__
    )


def scenario(name, uids, *, rule_id="TEST-001", available=None, label="malicious"):
    return {
        "scenario_id": name,
        "rule_id": rule_id,
        "split": "development",
        "label": label,
        "telemetry_complete": available is None,
        "anchor_event_uids": uids,
        "available_event_uids": uids if available is None else available,
    }


class GenericRuleTests(unittest.TestCase):
    def setUp(self):
        self.connection = connect()
        ingest(self.connection, ROOT / "fixtures/aws/synthetic/manifest.json")
        self.addCleanup(self.connection.close)
        self.events = rows(
            self.connection, "SELECT * FROM events ORDER BY timestamp,event_uid LIMIT 5"
        )
        self.uids = [event["event_uid"] for event in self.events]

    def test_single_pair_and_many_event_findings_and_scoring(self):
        for count in (1, 2, 3, 5):
            with self.subTest(count=count):
                sql = f"SELECT list(event_uid ORDER BY timestamp,event_uid) AS support FROM (SELECT * FROM events ORDER BY timestamp,event_uid LIMIT {count})"
                registry = test_registry(sql)
                result = detect(self.connection, registry=registry)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["event_uids"], self.uids[:count])
                self.assertEqual(
                    result[0]["source_event_ids"],
                    [event["source_event_id"] for event in self.events[:count]],
                )
                self.assertEqual(result, detect(self.connection, registry=registry))
                report = score(result, [scenario("case", self.uids[:count])], registry=registry)
                self.assertEqual(report["TEST-001"]["metrics"]["tp"], 1)
                explained = explain(self.connection, result[0]["finding_id"], registry=registry)
                self.assertEqual(
                    [event["event_uid"] for event in explained["events"]], self.uids[:count]
                )
                self.assertTrue(
                    all(
                        event["source_references"][0]["integrity_verified"]
                        for event in explained["events"]
                    )
                )
                self.assertEqual(
                    explained["execution"]["scope_parameters"],
                    {"provider": "aws", "source": "aws.cloudtrail"},
                )

    def test_scalar_columns_order_source_ids_and_duplicate_predicates(self):
        first, second = self.uids[:2]
        sql = f"SELECT '{second}' AS latest, '{first}' AS earliest, 'forged' AS source_event_id, value FROM (VALUES (1), (2)) AS predicates(value) ORDER BY value"
        registry = test_registry(sql, contract={"columns": ["latest", "earliest"]})
        finding = detect(self.connection, registry=registry)[0]
        self.assertEqual(finding["event_uids"], [second, first])
        self.assertEqual(
            finding["source_event_ids"],
            [self.events[1]["source_event_id"], self.events[0]["source_event_id"]],
        )
        self.assertEqual(len(finding["predicate_evidence"]), 2)
        expected_id = (
            "finding_"
            + digest(
                canonical(["TEST-001", "test-1", digest(sql.encode()), [second, first]]).encode()
            )[:24]
        )
        self.assertEqual(finding["finding_id"], expected_id)

    def test_invalid_or_unknown_evidence_is_rejected(self):
        for expression, message in [
            ("[]", "one or more"),
            ("[NULL]", "one or more"),
            ("['']", "one or more"),
            (f"['{self.uids[0]}', '{self.uids[0]}']", "unique"),
            (f"'{self.uids[0]}'", "one or more"),
            ("['missing']", "unknown event"),
        ]:
            with self.subTest(expression=expression):
                with self.assertRaisesRegex(ValueError, message):
                    detect(
                        self.connection, registry=test_registry(f"SELECT {expression} AS support")
                    )
        with self.assertRaisesRegex(ValueError, "omitted"):
            detect(self.connection, registry=test_registry("SELECT 1 AS other_column"))

    def test_wrong_provider_or_source_evidence_is_rejected(self):
        sql = f"SELECT ['{self.uids[0]}'] AS support"
        for provider, source in (("azure", "azure.activity"), ("aws", "test.other")):
            with self.subTest(provider=provider, source=source):
                with self.assertRaisesRegex(ValueError, "provider/source"):
                    detect(
                        self.connection,
                        registry=test_registry(sql, provider=provider, source=source),
                    )

    def test_registry_controls_revisions_without_rule_name_special_cases(self):
        baseline = catalog()
        candidate = catalog("restart-aware")
        self.assertEqual(revisions(), ("baseline", "restart-aware"))
        self.assertEqual(baseline["EITS-AWS-002"]["version"], "1.0.0")
        self.assertEqual(candidate["EITS-AWS-002"]["version"], "1.1.0")
        self.assertNotEqual(rule_sql("EITS-AWS-002"), rule_sql("EITS-AWS-002", "restart-aware"))
        registry = RuleRegistry({"custom-revision": {"NEW-RULE": baseline["EITS-AWS-001"]}})
        self.assertEqual(revisions(registry=registry), ("custom-revision",))
        self.assertEqual(
            rule_sql("NEW-RULE", "custom-revision", registry=registry), rule_sql("EITS-AWS-001")
        )
        with self.assertRaisesRegex(ValueError, "unknown rule revision"):
            catalog("missing", registry=registry)
        baseline["EITS-AWS-001"]["provider"] = "changed"
        self.assertEqual(catalog()["EITS-AWS-001"]["provider"], "aws")

    def test_scoped_execution_isolates_hunt_and_detection_counterevidence(self):
        baseline_hunt = hunt(self.connection)
        baseline_findings = detect(self.connection, "restart-aware")
        # A separately scoped event can reuse account/credential/actor values without
        # influencing this source's use counts or intervening-restart predicates.
        self.connection.execute("""INSERT INTO events BY NAME SELECT * REPLACE (
            'evt_other_source' AS event_uid, 'other-source-id' AS source_event_id,
            'test.other' AS source) FROM events WHERE action='AttachUserPolicy' LIMIT 1""")
        self.assertEqual(hunt(self.connection), baseline_hunt)
        self.assertEqual(detect(self.connection, "restart-aware"), baseline_findings)
        sql = "SELECT list(event_uid ORDER BY event_uid) AS support FROM events"
        finding = detect(self.connection, registry=test_registry(sql))[0]
        self.assertNotIn("evt_other_source", finding["event_uids"])

    def test_other_source_restart_cannot_suppress_a_sequence(self):
        before = detect(self.connection, "restart-aware")
        self.assertEqual(len(before), 8)
        self.connection.execute("UPDATE events SET source='test.other' WHERE action='StartLogging'")
        after = detect(self.connection, "restart-aware")
        self.assertEqual(len(after), 10)
        restored_accounts = {
            finding["predicate_evidence"][0]["account_id"]
            for finding in after
            if finding not in before
        }
        self.assertEqual(restored_accounts, {"900000000016", "900000000019"})

    def test_explain_context_uses_scope_and_never_email_or_account_alone(self):
        pair = detect(self.connection)[0]
        before = explain(self.connection, pair["finding_id"])
        first_uid = pair["event_uids"][0]
        # All other fields, including account and time, match an actual supporting event.
        for field, value in (
            ("provider", "other-provider"),
            ("source", "other-source"),
            ("scope_type", "other.scope"),
            ("scope_id", "other-scope"),
            ("tenant_id", "other-tenant"),
        ):
            self.connection.execute(
                f"""INSERT INTO events BY NAME SELECT * REPLACE (
                ? AS event_uid, ? AS {field}) FROM events WHERE event_uid=?""",
                ["context_" + field, value, first_uid],
            )
        after = explain(self.connection, pair["finding_id"])
        self.assertEqual(after["context_timeline"], before["context_timeline"])

    def test_unknown_scope_cannot_expand_context(self):
        uid = self.uids[0]
        self.connection.execute("UPDATE events SET scope_type=NULL,scope_id=NULL")
        registry = test_registry(f"SELECT ['{uid}'] AS support")
        finding = detect(self.connection, registry=registry)[0]
        explained = explain(self.connection, finding["finding_id"], registry=registry)
        self.assertEqual([event["event_uid"] for event in explained["context_timeline"]], [uid])

    def test_hash_manifest_covers_registry_adapters_and_executable_resources(self):
        hashes = package_hashes()
        for name in (
            "registry.py",
            "engine.py",
            "db.py",
            "adapters/__init__.py",
            "adapters/aws.py",
            "rules/registry.json",
            "rules/catalog.json",
            "rules/hunts.json",
            "rules/restart-aware.json",
            "sql/EITS-AWS-001.sql",
            "sql/HUNT-001.sql",
            "sql/schema.sql",
        ):
            self.assertIn(name, hashes)
            self.assertEqual(hashes[name], digest((ROOT / "src/eits" / name).read_bytes()))


class GenericScoringTests(unittest.TestCase):
    def setUp(self):
        self.registry = test_registry("SELECT [] AS support")

    def test_missing_arbitrary_anchor_and_wrong_evidence_remain_fn(self):
        for anchors in (["a"], ["a", "b"], ["a", "b", "c"]):
            with self.subTest(anchors=anchors):
                case = scenario("missing", anchors, available=["other"])
                result = score([], [case], registry=self.registry)["TEST-001"]["metrics"]
                self.assertEqual((result["tp"], result["fn"]), (0, 1))
                finding = {"finding_id": "wrong", "rule_id": "TEST-001", "event_uids": ["other"]}
                result = score([finding], [case], registry=self.registry)["TEST-001"]["metrics"]
                self.assertEqual((result["tp"], result["fp"], result["fn"]), (0, 1, 1))

    def test_uid_anchors_isolate_reused_source_ids(self):
        cases = [scenario("aws", ["evt_aws"]), scenario("azure", ["evt_azure"], label="benign")]
        findings = [
            {
                "finding_id": "aws-finding",
                "rule_id": "TEST-001",
                "event_uids": ["evt_aws"],
                "source_event_ids": ["same-source-id"],
                "provider": "aws",
                "source": "aws.cloudtrail",
            },
            {
                "finding_id": "azure-finding",
                "rule_id": "TEST-001",
                "event_uids": ["evt_azure"],
                "source_event_ids": ["same-source-id"],
                "provider": "azure",
                "source": "azure.activity",
            },
        ]
        result = score(findings, cases, registry=self.registry)["TEST-001"]["metrics"]
        self.assertEqual((result["tp"], result["fp"], result["fn"]), (1, 1, 0))
        findings[0]["event_uids"] = ["unassigned-other-scope"]
        result = score(findings, cases, registry=self.registry)["TEST-001"]["metrics"]
        self.assertEqual((result["tp"], result["fp"], result["fn"]), (0, 2, 1))

    def test_evidence_may_support_independent_rules(self):
        cases = [scenario("one", ["shared"]), scenario("two", ["shared"], rule_id="OTHER")]
        findings = [
            {"finding_id": "first", "rule_id": "TEST-001", "event_uids": ["shared"]},
            {"finding_id": "second", "rule_id": "OTHER", "event_uids": ["shared"]},
        ]
        result = score(findings, cases, registry=self.registry)
        self.assertEqual(result["TEST-001"]["metrics"]["tp"], 1)
        self.assertEqual(result["OTHER"]["metrics"]["tp"], 1)
        with self.assertRaisesRegex(ValueError, "shares an event"):
            score(
                [],
                [scenario("one", ["shared"]), scenario("two", ["shared"])],
                registry=self.registry,
            )

    def test_legacy_source_id_collisions_require_uid_anchors(self):
        case = scenario("one", ["same"])
        case["anchor_event_ids"] = case.pop("anchor_event_uids")
        case["available_event_ids"] = case.pop("available_event_uids")
        findings = [
            {
                "finding_id": f"f-{index}",
                "rule_id": "TEST-001",
                "source_event_ids": ["same"],
                "event_uids": [f"evt-{index}"],
                "provider": "aws",
                "source": "aws.cloudtrail",
            }
            for index in (1, 2)
        ]
        with self.assertRaisesRegex(ValueError, "ambiguous source event IDs"):
            score(findings, [case], registry=self.registry)
        findings[1]["source"] = "other-source"
        with self.assertRaisesRegex(ValueError, "multi-source"):
            score(findings, [case], registry=self.registry)

    def test_evaluate_checks_all_store_ids_for_legacy_ambiguity(self):
        # Same source ID in two accounts is valid ingestion, but not an unambiguous
        # legacy evaluation anchor even if only one occurrence alerts.
        original = json.loads((ROOT / "fixtures/aws/synthetic/case-01.json").read_text())[
            "Records"
        ][0]
        other = copy.deepcopy(original)
        other["recipientAccountId"] = "another-account"
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            content = json.dumps({"Records": [original, other]}).encode()
            (directory / "events.json").write_bytes(content)
            manifest = json.loads((ROOT / "fixtures/aws/synthetic/manifest.json").read_text())
            manifest["files"] = [
                {"path": "events.json", "format": "cloudtrail-json", "sha256": digest(content)}
            ]
            (directory / "manifest.json").write_text(json.dumps(manifest))
            case = scenario("one", [original["eventID"]])
            case["anchor_event_ids"] = case.pop("anchor_event_uids")
            case["available_event_ids"] = case.pop("available_event_uids")
            (directory / "truth.json").write_text(
                json.dumps({"dataset_id": manifest["dataset_id"], "scenarios": [case]})
            )
            with self.assertRaisesRegex(
                ValueError, "evaluation database require event UID anchors"
            ):
                evaluate(
                    directory / "manifest.json", directory / "truth.json", registry=self.registry
                )

    def test_empty_duplicate_and_mixed_anchor_modes_are_rejected(self):
        for uids in ([], ["a", "a"], [None]):
            with self.subTest(uids=uids):
                with self.assertRaisesRegex(ValueError, "anchors cannot be empty"):
                    score([], [scenario("one", uids)], registry=self.registry)
        legacy = scenario("legacy", ["id"])
        legacy["anchor_event_ids"] = legacy.pop("anchor_event_uids")
        legacy["available_event_ids"] = legacy.pop("available_event_uids")
        with self.assertRaisesRegex(ValueError, "must not mix"):
            score([], [scenario("uid", ["uid"]), legacy], registry=self.registry)

    def test_injected_source_adapter_evaluation_and_explanation_end_to_end(self):
        adapter = StubAdapter()
        adapters = AdapterRegistry([adapter])
        records = [
            {"id": f"event-{index}", "scope_id": "test-subscription", "tenant_id": "test-tenant"}
            for index in range(3)
        ]
        uids = sorted(adapter.normalize(record).event_uid for record in records)
        registry = test_registry(
            "SELECT list(event_uid ORDER BY event_uid) AS support FROM events",
            provider=adapter.provider,
            source=adapter.source,
        )
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            manifest = write_manifest(directory, records)
            truth = directory / "truth.json"
            truth.write_text(
                json.dumps({"dataset_id": "stub", "scenarios": [scenario("three", uids)]})
            )
            report = evaluate(manifest, truth, registry=registry, adapter_registry=adapters)
            self.assertEqual(report["rules"]["TEST-001"]["metrics"]["tp"], 1)
            self.assertEqual(report["evidence_events_verified"], 3)
            self.assertEqual(report["findings"][0]["event_uids"], uids)
            self.assertEqual(
                report["execution_scope"]["TEST-001"],
                {"provider": "azure", "source": "azure.activity"},
            )
            self.assertNotEqual(
                report["sql_sha256"]["TEST-001"], report["executed_query_sha256"]["TEST-001"]
            )
            connection = connect()
            try:
                ingest(connection, manifest, registry=adapters)
                explained = explain(
                    connection,
                    report["findings"][0]["finding_id"],
                    registry=registry,
                    adapter_registry=adapters,
                )
                self.assertTrue(
                    all(
                        event["source_references"][0]["integrity_verified"]
                        for event in explained["events"]
                    )
                )
                self.assertEqual(
                    [event["event_uid"] for event in explained["context_timeline"]], uids
                )
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
