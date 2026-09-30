"""Offline integration of all five sources through the shared investigation interface."""

import importlib.util
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from eits.adapters import source_catalog
from eits.cli import serialize
from eits.db import connect, evidence, ingest, rows
from eits.engine import catalog, detect, explain, hunt, hunt_catalog
from eits.evaluation import evaluate
from eits.model import event_uid

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = (
    "fixtures/aws/official/manifest.json",
    "fixtures/aws/synthetic/manifest.json",
    "fixtures/azure/activity/official/manifest.json",
    "fixtures/azure/activity/synthetic/manifest.json",
    "fixtures/azure/entra-signin/synthetic/manifest.json",
    "fixtures/azure/entra-audit/synthetic/manifest.json",
    "fixtures/gcp/synthetic/manifest.json",
)
SOURCES = {
    "aws.cloudtrail",
    "azure.activity",
    "azure.entra.signin",
    "azure.entra.audit",
    "gcp.audit",
}


class MulticloudTests(unittest.TestCase):
    def test_offline_ingestion_rules_hunts_evidence_and_aws_compatibility(self):
        with ExitStack() as stack:
            for name in ("socket.create_connection", "socket.socket.connect"):
                stack.enter_context(
                    patch(name, side_effect=AssertionError("runtime attempted network access"))
                )
            connection, aws_only = connect(), connect()
            stack.callback(connection.close)
            stack.callback(aws_only.close)
            for manifest in MANIFESTS:
                ingest(connection, ROOT / manifest)
                if "/aws/" in manifest:
                    ingest(aws_only, ROOT / manifest)

            self.assertEqual(
                {row["source"] for row in rows(connection, "SELECT DISTINCT source FROM events")},
                SOURCES,
            )
            self.assertEqual(
                {entry["source"] for entry in source_catalog() if entry["implemented"]}, SOURCES
            )
            self.assertEqual(len(catalog()), 6)
            self.assertEqual(set(hunt_catalog()), {"HUNT-001", "HUNT-002", "HUNT-003"})
            findings = detect(connection)
            self.assertEqual({finding["rule_id"] for finding in findings}, set(catalog()))
            self.assertEqual({len(finding["event_uids"]) for finding in findings}, {1, 2})
            self.assertEqual(
                [finding for finding in findings if finding["provider"] == "aws"],
                detect(aws_only),
            )
            self.assertEqual(
                hunt(connection, hunt_id="HUNT-001"), hunt(aws_only, hunt_id="HUNT-001")
            )
            for finding in findings:
                resolved = explain(connection, finding["finding_id"])
                self.assertEqual(
                    [event["event_uid"] for event in resolved["events"]], finding["event_uids"]
                )
                self.assertEqual(resolved["rule_version"], catalog()[finding["rule_id"]]["version"])
                self.assertEqual(len(resolved["sql_sha256"]), 64)
                for field in ("observed", "inferred", "unresolved", "predicate_evidence"):
                    self.assertTrue(resolved[field])
                for event in resolved["events"]:
                    self.assertEqual(
                        (event["provider"], event["source"]),
                        (finding["provider"], finding["source"]),
                    )
                    self.assertTrue(
                        all(
                            reference["integrity_verified"]
                            for reference in event["source_references"]
                        )
                    )
                    self.assertEqual(
                        event["event_uid"],
                        event_uid(
                            event["provider"],
                            event["source"],
                            event["raw"],
                            scope_type=event["scope_type"],
                            scope_id=event["scope_id"],
                            tenant_id=event["tenant_id"],
                        ),
                    )
                    self.assertEqual(evidence(connection, event["event_uid"])["raw"], event["raw"])

            for hunt_id, metadata in hunt_catalog().items():
                leads = hunt(connection, hunt_id=hunt_id)
                self.assertTrue(leads, hunt_id)
                for lead in leads:
                    self.assertNotIn("finding_id", lead)
                    self.assertNotIn("severity", lead)
                    uids = []
                    for key, value in lead.items():
                        if key.endswith("_uids") and isinstance(value, list):
                            uids.extend(value)
                        elif key.endswith("_uid") and isinstance(value, str):
                            uids.append(value)
                    self.assertTrue(uids, (hunt_id, lead))
                    for uid in uids:
                        event = evidence(connection, uid)
                        self.assertEqual(event["source"], metadata["source"])

            # Evaluation still executes only the source declared by its manifest.
            aws_report = evaluate(ROOT / MANIFESTS[1], ROOT / "evaluation/ground_truth.json")
            frozen = json.loads((ROOT / "evaluation/refactor-baseline.json").read_text())
            self.assertEqual(set(aws_report["rules"]), {"EITS-AWS-001", "EITS-AWS-002"})
            self.assertEqual(aws_report["rules"], frozen["rules"])
            self.assertEqual(
                json.loads(json.dumps(aws_report["findings"], default=serialize)),
                frozen["findings"],
            )

    def test_synthetic_generators_reproduce_checked_in_artifacts_without_network(self):
        definitions = (
            (
                "generate_azure_activity",
                ("generate",),
                "fixtures/azure/activity/synthetic",
                "evaluation/azure-activity-ground-truth.json",
            ),
            (
                "generate_entra",
                ("generate_audit", "generate_signins"),
                "fixtures/azure/entra-audit/synthetic",
                "evaluation/entra-ground-truth.json",
            ),
            (
                "generate_gcp",
                ("generate",),
                "fixtures/gcp/synthetic",
                "evaluation/gcp-ground-truth.json",
            ),
        )
        for name, functions, fixture_path, truth_path in definitions:
            with (
                self.subTest(generator=name),
                tempfile.TemporaryDirectory() as directory,
                ExitStack() as stack,
            ):
                for network in ("socket.create_connection", "socket.socket.connect"):
                    stack.enter_context(
                        patch(
                            network,
                            side_effect=AssertionError("generator attempted network access"),
                        )
                    )
                spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                target = Path(directory)
                (target / "evaluation").mkdir()
                stack.enter_context(patch.object(module, "ROOT", target))
                for function in functions:
                    if name == "generate_azure_activity":
                        getattr(module, function)(root=target)
                    else:
                        getattr(module, function)()
                expected = {path.relative_to(ROOT) for path in (ROOT / fixture_path).glob("*.json")}
                expected.add(Path(truth_path))
                if name == "generate_entra":
                    expected.update(
                        path.relative_to(ROOT)
                        for path in (ROOT / "fixtures/azure/entra-signin/synthetic").glob("*.json")
                    )
                generated = {path.relative_to(target) for path in target.rglob("*.json")}
                self.assertEqual(generated, expected)
                for relative in sorted(expected):
                    self.assertEqual(
                        (target / relative).read_bytes(),
                        (ROOT / relative).read_bytes(),
                        str(relative),
                    )


if __name__ == "__main__":
    unittest.main()
