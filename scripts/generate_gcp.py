"""Deterministic original GCP schema fixtures; no network or cloud dependencies."""

import copy
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eits.adapters.gcp import AUDIT_TYPE, GcpAuditAdapter
from eits.model import digest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [
    "https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry",
    "https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog",
    "https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys",
    "https://docs.cloud.google.com/iam/docs/audit-logging/examples-service-accounts",
    "https://docs.cloud.google.com/resource-manager/docs/audit-logging",
    "https://docs.cloud.google.com/storage/docs/audit-logging",
    "https://github.com/googleapis/googleapis/blob/master/google/iam/v1/logging/audit_data.proto",
    "https://github.com/googleapis/googleapis/blob/master/google/iam/v1/policy.proto",
]


def entry(number, tag, service, method, seconds=0):
    project = f"eits-lab-{number:03d}"
    return {
        "logName": f"projects/{project}/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": uuid.uuid5(uuid.NAMESPACE_URL, f"eits:gcp:1:{number}:{tag}").hex,
        "timestamp": (datetime(2025, 4, 5, 12, tzinfo=timezone.utc) + timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z"),
        "resource": {"type": "project", "labels": {"project_id": project}},
        "protoPayload": {
            "@type": AUDIT_TYPE,
            "serviceName": service,
            "methodName": method,
            "status": {"code": 0},
            "authenticationInfo": {
                "principalSubject": "user:operator@example.invalid",
                "principalEmail": "operator@example.invalid",
            },
            "requestMetadata": {
                "callerIp": "192.0.2.30",
                "callerSuppliedUserAgent": "eits-synthetic/1",
            },
            "resourceName": f"projects/{project}",
        },
    }


def key_pair(number):
    a = entry(
        number, "creation", "iam.googleapis.com", "google.iam.admin.v1.CreateServiceAccountKey"
    )
    project = f"eits-lab-{number:03d}"
    account = f"workload@{project}.iam.gserviceaccount.com"
    key_name = f"projects/{project}/serviceAccounts/{account}/keys/{number:040x}"
    a["protoPayload"]["request"] = {"name": f"projects/{project}/serviceAccounts/{account}"}
    a["protoPayload"]["response"] = {
        "@type": "type.googleapis.com/google.iam.admin.v1.ServiceAccountKey",
        "name": key_name,
        "keyType": "USER_MANAGED",
    }
    a["resource"]["type"] = "service_account"
    b = entry(number, "policy", "cloudresourcemanager.googleapis.com", "SetIamPolicy", 300)
    b["protoPayload"]["authenticationInfo"] = {
        "principalSubject": f"serviceAccount:{account}",
        "principalEmail": account,
        "serviceAccountKeyName": "//iam.googleapis.com/" + key_name,
    }
    b["protoPayload"]["request"] = {
        "resource": project,
        "policy": {
            "bindings": [{"role": "roles/editor", "members": ["user:recipient@example.invalid"]}]
        },
    }
    return a, b


def bucket_change(number, member="allUsers", role="roles/storage.objectViewer"):
    value = entry(number, "bucket-policy", "storage.googleapis.com", "storage.setIamPermissions")
    value["resource"]["type"] = "gcs_bucket"
    value["resource"]["labels"]["bucket_name"] = f"eits-bucket-{number:03d}"
    value["protoPayload"]["resourceName"] = f"projects/_/buckets/eits-bucket-{number:03d}"
    value["protoPayload"]["serviceData"] = {
        "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
        "policyDelta": {"bindingDeltas": [{"action": "ADD", "member": member, "role": role}]},
    }
    return value


def generate():
    target = ROOT / "fixtures/gcp/synthetic"
    target.mkdir(parents=True, exist_ok=True)
    truth, specs = [], []
    adapter = GcpAuditAdapter()

    def save(number, rule, label, reason, anchors, available=None, complete=True):
        available = copy.deepcopy(anchors if available is None else available)
        noise = entry(
            number, "background", "cloudresourcemanager.googleapis.com", "GetIamPolicy", 120
        )
        available.append(noise)
        content = (json.dumps({"entries": available}, indent=2) + "\n").encode()
        name = f"case-{number:03d}.json"
        (target / name).write_bytes(content)
        specs.append({"path": name, "sha256": digest(content), "format": "gcp-audit-json"})
        truth.append(
            {
                "scenario_id": f"gcp-{number:03d}",
                "rule_id": rule,
                "label": label,
                "split": "development" if number % 2 else "holdout",
                "telemetry_complete": complete,
                "description": reason,
                "anchor_event_uids": [adapter.normalize(raw).event_uid for raw in anchors],
                "available_event_uids": [adapter.normalize(raw).event_uid for raw in available],
            }
        )

    key_cases = [
        ("malicious", "Unauthorized new key used for project policy change", True),
        (
            "benign",
            "Approved credential rotation and deployment; identical detector-visible sequence",
            True,
        ),
        ("ambiguous", "New key and policy change with unavailable authorization history", True),
        ("malicious", "Unauthorized sequence; creation response key name is absent", False),
        ("malicious", "Unauthorized policy use; key-creation record is missing", False),
        ("malicious", "Unauthorized use delayed until 40 minutes; outside rule window", True),
        ("benign", "Denied policy update during a deployment test", True),
        ("benign", "Independent existing key performs policy update", True),
        (
            "benign",
            "Approved cross-project administration is deliberately outside same-project rule",
            True,
        ),
        ("malicious", "Unauthorized use exactly at the inclusive 30-minute boundary", True),
        ("benign", "Coarse equal timestamps cannot establish sequence ordering", True),
        ("malicious", "Unauthorized sequence with absent operation status", False),
        ("benign", "Approved key creation without observed subsequent use", True),
        ("malicious", "Unauthorized use one second beyond the rule boundary", True),
        ("malicious", "Key path wildcard spelling differs; no unsupported alias inference", True),
    ]
    for number, (label, reason, complete) in enumerate(key_cases, 1):
        a, b = key_pair(number)
        available = None
        if number == 4:
            a["protoPayload"]["response"].pop("name")
        elif number == 5:
            available = [b]
        elif number in (6, 10, 11, 14):
            seconds = {6: 2400, 10: 1800, 11: 0, 14: 1801}[number]
            b["timestamp"] = entry(number, "temporary", "x", "x", seconds)["timestamp"]
        elif number == 7:
            b["protoPayload"]["status"] = {"code": 7, "message": "Permission denied"}
        elif number == 8:
            b["protoPayload"]["authenticationInfo"]["serviceAccountKeyName"] += "other"
        elif number == 9:
            b["logName"] = b["logName"].replace("eits-lab-009", "eits-other-009")
        elif number == 12:
            b["protoPayload"].pop("status")
        elif number == 13:
            available = [a]
        elif number == 15:
            a["protoPayload"]["response"]["name"] = a["protoPayload"]["response"]["name"].replace(
                "projects/eits-lab-015/", "projects/-/"
            )
        save(
            number,
            "EITS-GCP-001",
            label,
            reason,
            [a] if number == 13 else [a, b],
            available,
            complete,
        )

    bucket_cases = [
        ("malicious", "Unauthorized anonymous object-read grant", True),
        ("malicious", "Unauthorized broad authenticated object-administration grant", True),
        ("benign", "Approved open-data publication; same visible grant as malicious case", True),
        ("ambiguous", "Public grant with unknown dataset classification and approval", True),
        ("malicious", "Unauthorized grant; policy delta missing from retained event", False),
        ("malicious", "Unauthorized grant; status null and success unresolvable", False),
        ("benign", "Removal of an old public grant", True),
        ("benign", "Denied request cannot establish completed public grant", True),
        ("benign", "Approved object access granted to a named service account", True),
        (
            "benign",
            "Public viewer removal and private viewer addition occur in separate deltas",
            True,
        ),
        (
            "malicious",
            "Unauthorized public grant uses a custom object-access role outside fixed role list",
            True,
        ),
        ("benign", "Non-Storage service event must not trigger the bucket rule", True),
        ("malicious", "Unauthorized grant; target resource name lost", False),
        (
            "malicious",
            "Unauthorized grant represented only in generic metadata, outside supported delta shape",
            False,
        ),
        (
            "benign",
            "Approved publication to two broad principals; one finding retains both delta rows",
            True,
        ),
    ]
    for number, (label, reason, complete) in enumerate(bucket_cases, 101):
        value = bucket_change(number)
        payload = value["protoPayload"]
        deltas = payload["serviceData"]["policyDelta"]["bindingDeltas"]
        if number == 102:
            deltas[0].update(member="allAuthenticatedUsers", role="roles/storage.objectAdmin")
        elif number == 105:
            payload.pop("serviceData")
        elif number == 106:
            payload["status"] = None
        elif number == 107:
            deltas[0]["action"] = "REMOVE"
        elif number == 108:
            payload["status"] = {"code": 7, "message": "Permission denied"}
        elif number == 109:
            deltas[0]["member"] = "serviceAccount:reader@eits-lab-109.iam.gserviceaccount.com"
        elif number == 110:
            deltas[0]["action"] = "REMOVE"
            deltas.append(
                {
                    "action": "ADD",
                    "role": "roles/storage.objectViewer",
                    "member": "user:reader@example.invalid",
                }
            )
        elif number == 111:
            deltas[0]["role"] = "projects/eits-lab-111/roles/objectReader"
        elif number == 112:
            payload["serviceName"] = "example.googleapis.com"
        elif number == 113:
            payload.pop("resourceName")
        elif number == 114:
            payload["metadata"] = payload.pop("serviceData")
        elif number == 115:
            deltas.append(
                {
                    "action": "ADD",
                    "role": "roles/storage.objectViewer",
                    "member": "allAuthenticatedUsers",
                }
            )
        save(number, "EITS-GCP-002", label, reason, [value], complete=complete)

    manifest = {
        "dataset_id": "gcp-synthetic-v1",
        "provider": "gcp",
        "source": "gcp.audit",
        "category": "synthetic",
        "source_urls": SOURCES,
        "license": "MIT; original independently generated fixtures based on public Google schemas",
        "modified": True,
        "limitations": [
            "Fictional offline scenarios; no live cloud validation",
            "Not official examples or repaired excerpts",
            "No operational-rate or representativeness claim",
            "Policy intent and telemetry-loss labels reside only in separate ground truth",
            "Explicit success status and key response name are not universal in real logs",
        ],
        "files": specs,
    }
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (ROOT / "evaluation/gcp-ground-truth.json").write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "dataset_id": "gcp-synthetic-v1",
                "source": "gcp.audit",
                "scenarios": truth,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    generate()
