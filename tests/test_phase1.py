import copy
import json
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from eits.db import connect, evidence, ingest, records, rows
from eits.engine import detect, hunt
from eits.evaluation import score
from eits.model import canonical, digest, normalize

ROOT = Path(__file__).resolve().parents[1]


def case(number):
    events = json.loads((ROOT / f"fixtures/aws/synthetic/case-{number:02d}.json").read_text())["Records"]
    return [e for e in events if e["eventName"] != "DescribeInstances"]


def manifest_for(directory, events, filename="events.json", format_name="cloudtrail-json"):
    content = (json.dumps({"Records": events}) if format_name == "cloudtrail-json"
               else "\n".join(json.dumps(e) for e in events)).encode()
    (directory / filename).write_bytes(content)
    manifest = {"dataset_id": "unit-fixture", "provider": "aws", "source": "aws.cloudtrail",
                "category": "synthetic", "license": "MIT", "modified": True,
                "source_urls": ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html"],
                "limitations": ["Synthetic test variant of project fixtures"],
                "files": [{"path": filename, "format": format_name, "sha256": digest(content)}]}
    path = directory / "manifest.json"
    path.write_text(json.dumps(manifest))
    return path


@contextmanager
def database(events):
    connection = connect()
    try:
        with tempfile.TemporaryDirectory() as directory:
            ingest(connection, manifest_for(Path(directory), events))
        yield connection  # Evidence must survive removal of original input files.
    finally:
        connection.close()


class ParserAndProvenanceTests(unittest.TestCase):
    def test_standalone_record_pointer_and_missing_provenance(self):
        raw = case(1)[0]
        self.assertEqual(list(records(json.dumps(raw).encode(), "cloudtrail-json")), [("", raw)])
        con = connect()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = manifest_for(Path(directory), [raw])
                manifest = json.loads(path.read_text())
                manifest.pop("license")
                path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError, "provenance"):
                    ingest(con, path)
        finally:
            con.close()

    def test_official_examples_and_independent_oracles(self):
        con = connect()
        try:
            result = ingest(con, ROOT / "fixtures/aws/official/manifest.json")
            self.assertEqual(result["new_events"], 7)
            start = rows(con, "SELECT * FROM events WHERE action='StartInstances'")[0]
            self.assertEqual(start["source_event_id"], "e755e09c-42f9-4c5c-9064-EXAMPLE228c7")
            self.assertEqual(start["timestamp"], datetime(2023, 7, 19, 21, 17, 28, tzinfo=timezone.utc))
            self.assertEqual(start["account_id"], "123456789012")
            self.assertEqual(start["source_ip"], "192.0.2.0")
            self.assertEqual(start["actor_arn"], "arn:aws:iam::123456789012:user/Mateo")
            self.assertEqual(start["outcome"], "success")
            failed = rows(con, "SELECT * FROM events WHERE action='UpdateTrail'")[0]
            self.assertEqual(failed["outcome"], "failure")
            self.assertEqual(failed["error_code"], "TrailNotFoundException")
            self.assertEqual(detect(con), [])
            for uid, in con.execute("SELECT event_uid FROM events").fetchall():
                self.assertTrue(evidence(con, uid)["source_references"][0]["integrity_verified"])
        finally:
            con.close()

    def test_normalization_does_not_modify_source(self):
        raw = case(1)[0]
        raw["resources"] = [{"ARN": "arn:aws:iam::900000000001:user/example"}]
        before = canonical(raw)
        normalize(raw)
        self.assertEqual(canonical(raw), before)

    def test_unknowns_are_not_false_or_success(self):
        raw = case(1)[0]
        raw.pop("eventType")
        raw.pop("eventTime")
        raw.pop("eventID")
        raw["sourceIPAddress"] = "iam.amazonaws.com"
        parsed = normalize(raw)
        self.assertEqual(parsed["outcome"], "unknown")
        self.assertIsNone(parsed["timestamp"])
        self.assertIsNone(parsed["source_event_id"])
        self.assertIsNone(parsed["source_ip"])
        self.assertIsNone(json.loads(parsed["authentication"])["mfa_authenticated"])
        self.assertEqual(parsed["source_address"], "iam.amazonaws.com")

    def test_invalid_timezone_rejected(self):
        raw = case(1)[0]
        raw["eventTime"] = "2025-02-03T12:00:00"
        with self.assertRaisesRegex(ValueError, "timezone"):
            normalize(raw)

    def test_jsonl_idempotence_and_local_artifact_survival(self):
        con = connect()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = manifest_for(Path(directory), case(1), "events.jsonl", "jsonl")
                self.assertEqual(ingest(con, path)["new_events"], 2)
                self.assertEqual(ingest(con, path)["new_events"], 0)
            finding = detect(con)[0]
            item = evidence(con, finding["event_uids"][0])
            self.assertTrue(item["source_references"][0]["integrity_verified"])
            self.assertTrue(item["source_references"][0]["record_pointer"].startswith("line:"))
        finally:
            con.close()

    def test_tampered_fixture_rolls_back(self):
        con = connect()
        try:
            with tempfile.TemporaryDirectory() as directory:
                directory = Path(directory)
                path = manifest_for(directory, case(1))
                (directory / "events.json").write_text("{}")
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    ingest(con, path)
            self.assertEqual(con.execute("SELECT count(*) FROM events").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT count(*) FROM datasets").fetchone()[0], 0)
        finally:
            con.close()

    def test_path_escape_rejected(self):
        con = connect()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = manifest_for(Path(directory), case(1))
                value = json.loads(path.read_text())
                value["files"][0]["path"] = "../outside.json"
                path.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, "inside"):
                    ingest(con, path)
        finally:
            con.close()

    def test_conflicting_source_event_id_rejected(self):
        events = case(1)
        other = copy.deepcopy(events[0])
        other["sourceIPAddress"] = "198.51.100.8"
        with self.assertRaisesRegex(ValueError, "conflicting"):
            with database(events + [other]):
                pass

    def test_stored_evidence_integrity_failure(self):
        with database(case(1)) as con:
            uid = detect(con)[0]["event_uids"][0]
            con.execute("UPDATE artifacts SET content=?", [b"tampered"])
            with self.assertRaisesRegex(ValueError, "integrity"):
                evidence(con, uid)

    def test_duckdb_external_io_disabled(self):
        with database(case(1)) as con:
            self.assertFalse(con.execute("SELECT current_setting('enable_external_access')").fetchone()[0])
            columns = [r[1] for r in con.execute("PRAGMA table_info('events')").fetchall()]
            self.assertNotIn("label", columns)
            self.assertNotIn("scenario_id", columns)


class DetectionTests(unittest.TestCase):
    def test_runtime_functions_work_without_python_network_access(self):
        from unittest.mock import patch
        with patch("socket.socket.connect", side_effect=AssertionError("runtime attempted network access")):
            with database(case(1)) as con:
                finding = detect(con)[0]
                self.assertTrue(evidence(con, finding["event_uids"][0])["source_references"])
                self.assertEqual(len(hunt(con)), 1)

    def test_required_pair_uses_distinct_creator_and_key_owner(self):
        with database(case(1)) as con:
            finding = detect(con)[0]
            self.assertEqual(finding["rule_id"], "EITS-AWS-001")
            values = finding["predicate_evidence"][0]
            self.assertNotEqual(values["key_creator"], values["policy_actor"])
            self.assertEqual(values["elapsed_seconds"], 300)

    def test_direct_key_window_boundaries(self):
        for when, expected in [("12:00:00", 0), ("12:00:01", 1), ("12:30:00", 1), ("12:30:01", 0), ("11:59:59", 0)]:
            with self.subTest(when=when):
                events = case(1)
                next(e for e in events if e["eventName"] == "AttachUserPolicy")["eventTime"] = f"2025-02-03T{when}Z"
                with database(events) as con:
                    self.assertEqual(len(detect(con)), expected)

    def test_failed_or_unrelated_credentials_do_not_alert(self):
        for number in (7, 8, 11, 12):
            with self.subTest(case=number), database(case(number)) as con:
                self.assertEqual(detect(con), [])

    def test_cross_account_and_unknown_outcome_do_not_alert(self):
        for change in ("account", "outcome"):
            events = case(1)
            target = next(e for e in events if e["eventName"] == "AttachUserPolicy")
            if change == "account":
                target["recipientAccountId"] = "900000000099"
            else:
                target.pop("eventType")
            with database(events) as con:
                self.assertEqual(detect(con), [])

    def test_ipv4_ipv6_and_same_permission_requirement(self):
        for number, expected in [(13, 1), (14, 1), (17, 0), (20, 0), (22, 0), (23, 0), (24, 0)]:
            with self.subTest(case=number), database(case(number)) as con:
                self.assertEqual(len(detect(con)), expected)

    def test_same_ip_does_not_join_different_principal_or_credential(self):
        for field in ("principalId", "accessKeyId"):
            events = case(13)
            target = next(e for e in events if e["eventName"] == "AuthorizeSecurityGroupIngress")
            target["userIdentity"][field] = "different"
            with database(events) as con:
                self.assertEqual(detect(con), [])

    def test_ingress_failures_and_udp_do_not_alert(self):
        for change in ("failure", "udp"):
            events = case(13)
            target = next(e for e in events if e["eventName"] == "AuthorizeSecurityGroupIngress")
            if change == "failure":
                target["responseElements"]["_return"] = False
            else:
                target["requestParameters"]["ipPermissions"]["items"][0]["ipProtocol"] = "udp"
            with database(events) as con:
                self.assertEqual(detect(con), [])

    def test_duplicate_delivery_and_order_do_not_change_findings(self):
        events = case(13)
        with database(events) as con:
            first = detect(con)
        with database(list(reversed(events)) + events) as con:
            self.assertEqual(detect(con), first)

    def test_restart_candidate_removes_benign_and_malicious_pairs(self):
        for number in (16, 19):
            with self.subTest(case=number), database(case(number)) as con:
                self.assertEqual(len(detect(con, "baseline")), 1)
                self.assertEqual(detect(con, "restart-aware"), [])

    def test_unrelated_or_failed_restart_cannot_suppress(self):
        for change in ("trail", "outcome", "equal-time"):
            events = case(19)
            restart = next(e for e in events if e["eventName"] == "StartLogging")
            if change == "trail":
                restart["requestParameters"]["name"] = "other-trail"
            elif change == "outcome":
                restart["errorCode"] = "AccessDenied"
            else:
                restart["eventTime"] = "2025-02-03T12:05:00Z"
            with database(events) as con:
                self.assertEqual(len(detect(con, "restart-aware")), 1)

    def test_hunt_keeps_unused_unresolvable_and_late_activity(self):
        con = connect()
        try:
            ingest(con, ROOT / "fixtures/aws/synthetic/manifest.json")
            result = hunt(con)
            self.assertEqual(len(result), 12)
            self.assertEqual(sum(r["observation"] == "unresolvable" for r in result), 1)
            # Unused key, dropped use event, and an attachment made with an unrelated old key.
            self.assertEqual(sum(r["observation"] == "no_use_observed" for r in result), 3)
            late = next(r for r in result if r["account_id"] == "900000000003")
            self.assertEqual(late["sensitive_actions"], 1)
            self.assertEqual(late["event_count"], 1)
        finally:
            con.close()


class ScoringTests(unittest.TestCase):
    def test_ambiguous_and_missing_evidence_handling(self):
        cases = [
            {"scenario_id": "positive", "rule_id": "EITS-AWS-001", "split": "development", "label": "malicious", "telemetry_complete": False,
             "anchor_event_ids": ["a", "b"], "available_event_ids": ["a", "c"]},
            {"scenario_id": "uncertain", "rule_id": "EITS-AWS-001", "split": "development", "label": "ambiguous", "telemetry_complete": True,
             "anchor_event_ids": ["x", "y"], "available_event_ids": ["x", "y"]},
        ]
        findings = [{"rule_id": "EITS-AWS-001", "finding_id": "wrong-evidence", "source_event_ids": ["a", "c"]},
                    {"rule_id": "EITS-AWS-001", "finding_id": "uncertain", "source_event_ids": ["x", "y"]}]
        metrics = score(findings, cases)["EITS-AWS-001"]["metrics"]
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["fn"]), (0, 1, 1))
        self.assertEqual(metrics["ambiguous_alerted"], 1)
        self.assertIsNone(metrics["complete_telemetry_recall"])

    def test_duplicate_findings_cannot_inflate_true_positives(self):
        scenario = {"scenario_id": "case", "rule_id": "EITS-AWS-001", "split": "development", "label": "malicious", "telemetry_complete": True,
                    "anchor_event_ids": ["a", "b"], "available_event_ids": ["a", "b"]}
        finding = {"rule_id": "EITS-AWS-001", "finding_id": "one", "source_event_ids": ["a", "b"]}
        metrics = score([finding, {**finding, "finding_id": "two"}], [scenario])["EITS-AWS-001"]["metrics"]
        self.assertEqual(metrics["tp"], 1)
        self.assertEqual(metrics["duplicate_findings"], 1)


if __name__ == "__main__":
    unittest.main()
