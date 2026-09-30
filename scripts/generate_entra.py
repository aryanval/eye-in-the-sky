"""Deterministic fictional Graph v1.0 records; no network or live tenant access."""

import copy
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eits.model import event_uid

ROOT = Path(__file__).resolve().parents[1]
TENANT = str(uuid.uuid5(uuid.NAMESPACE_URL, "eits:entra:fictional-collection-tenant"))
SCOPE = {"scope_type": "azure.tenant", "scope_id": TENANT, "tenant_id": TENANT}
SOURCES = [
    "https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0",
    "https://learn.microsoft.com/en-us/graph/api/resources/targetresource?view=graph-rest-1.0",
    "https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0",
    "https://learn.microsoft.com/en-us/graph/api/resources/signinstatus?view=graph-rest-1.0",
    "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities",
]


def identifier(name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "eits:entra:synthetic-v1:" + name))


def timestamp(seconds):
    return (
        (datetime(2025, 4, 1, 12, tzinfo=timezone.utc) + timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )


def audit(number, tag, action, seconds=0):
    return {
        "id": identifier(f"{number}:{tag}"),
        "activityDateTime": timestamp(seconds),
        "activityDisplayName": action,
        "category": "ApplicationManagement",
        "correlationId": identifier(f"{number}:{tag}:correlation"),
        "result": "success",
        "resultReason": None,
        "loggedByService": "Core Directory",
        "operationType": "Add",
        "initiatedBy": {
            "user": {
                "id": identifier(f"{number}:operator"),
                "displayName": "Synthetic operator",
                "userPrincipalName": "operator@example.invalid",
                "ipAddress": "192.0.2.44",
            },
            "app": None,
        },
        "targetResources": [
            {
                "id": identifier(f"{number}:principal"),
                "type": "ServicePrincipal",
                "displayName": "Synthetic application",
                "modifiedProperties": [],
            }
        ],
        "additionalDetails": [],
    }


def uid(raw, source="azure.entra.audit"):
    return event_uid("azure", source, raw, **SCOPE)


def write_json(path, value):
    content = (json.dumps(value, indent=2) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def manifest(directory, source, dataset, files):
    return write_json(
        directory / "manifest.json",
        {
            "dataset_id": dataset,
            "provider": "azure",
            "source": source,
            "collection_scope": SCOPE,
            "category": "synthetic",
            "source_urls": SOURCES,
            "license": "MIT",
            "modified": True,
            "generation": "scripts/generate_entra.py; independently generated values using public Graph v1.0 resource properties and audit activity names, not repaired vendor examples",
            "limitations": [
                "Fictional records, not live tenant telemetry",
                "Audit target typing and operation-specific payload coverage are schema-based assumptions, not live validation",
                "No role sensitivity, credential use, or actor authorization is established",
            ],
            "files": files,
        },
    )


def generate_audit():
    directory = ROOT / "fixtures/azure/entra-audit/synthetic"
    cases = [
        (
            "malicious",
            True,
            "Unauthorized service-principal credential and application-role changes.",
        ),
        (
            "malicious",
            True,
            "Unauthorized sequence exactly at the inclusive thirty-minute boundary.",
        ),
        (
            "benign",
            True,
            "Approved application provisioning performs identical credential and role operations.",
        ),
        (
            "benign",
            True,
            "Authorized rotation and app-role maintenance share an administrator and target.",
        ),
        ("ambiguous", True, "Both operations are visible but approval and intent are unavailable."),
        (
            "malicious",
            False,
            "Credential addition retained; subsequent unauthorized assignment event is absent.",
        ),
        ("malicious", False, "Unauthorized sequence has no usable target ID on the assignment."),
        ("malicious", True, "Unauthorized role assignment delayed beyond the correlation window."),
        ("benign", True, "Approved credential operation followed by a failed role assignment."),
        ("benign", True, "Unrelated administrators make separate changes to the same target."),
        ("benign", True, "One administrator changes different service principals."),
        (
            "ambiguous",
            False,
            "Credential change alone; subsequent activity and approval are unavailable.",
        ),
        ("benign", True, "Equal timestamps do not establish an ordered sequence."),
        ("malicious", False, "Unauthorized sequence lacks the initiating user object ID."),
        ("malicious", False, "Only the assignment is retained; credential addition is missing."),
        ("malicious", False, "Unauthorized assignment timestamp is missing."),
        ("benign", True, "Approved role assignment precedes the credential addition."),
        ("malicious", True, "Unauthorized sequence has a one-second positive ordering interval."),
    ]
    files, scenarios = [], []
    for number, (label, complete, narrative) in enumerate(cases, 1):
        first = audit(number, "credential", "Add service principal credentials")
        second = audit(number, "assignment", "Add app role assignment to service principal", 600)
        if number == 2:
            second["activityDateTime"] = timestamp(1800)
        if number == 7:
            second["targetResources"][0]["id"] = None
        if number == 8:
            second["activityDateTime"] = timestamp(1801)
        if number == 9:
            second["result"] = "failure"
        if number == 10:
            second["initiatedBy"]["user"]["id"] = identifier("unrelated-operator")
        if number == 11:
            second["targetResources"][0]["id"] = identifier("unrelated-target")
        if number == 13:
            second["activityDateTime"] = timestamp(0)
        if number == 14:
            second["initiatedBy"]["user"]["id"] = None
        if number == 16:
            second["activityDateTime"] = None
        if number == 17:
            second["activityDateTime"] = timestamp(-1)
        if number == 18:
            second["activityDateTime"] = timestamp(1)
        anchors = [uid(first), uid(second)]
        available = [first, second]
        if number in (6, 12):
            available = [first]
        if number == 15:
            available = [second]
        for tag, action in (
            ("noise-one", "Update service principal"),
            ("noise-two", "Add owner to application"),
        ):
            noise = audit(number, tag, action, 300)
            noise["targetResources"][0]["id"] = identifier(f"noise:{number}:{tag}")
            available.append(noise)
        filename = f"case-{number:02d}.json"
        sha = write_json(directory / filename, {"value": available})
        files.append({"path": filename, "format": "graph-directory-audit-json", "sha256": sha})
        scenarios.append(
            {
                "scenario_id": f"entra-{number:02d}",
                "rule_id": "EITS-ENTRA-001",
                "split": "development" if number % 2 else "holdout",
                "label": label,
                "telemetry_complete": complete,
                "narrative": narrative,
                "anchor_event_uids": anchors,
                "available_event_uids": [uid(raw) for raw in available],
            }
        )
    dataset = "entra-audit-synthetic-v1"
    manifest(directory, "azure.entra.audit", dataset, files)
    write_json(
        ROOT / "evaluation/entra-ground-truth.json",
        {"version": 2, "dataset_id": dataset, "scenarios": scenarios},
    )


def generate_signins():
    directory = ROOT / "fixtures/azure/entra-signin/synthetic"
    events = []
    for index in range(12):
        raw = {
            "id": identifier(f"signin:{index}"),
            "createdDateTime": timestamp(index * 300),
            "userId": identifier(f"signin-user:{index // 4}"),
            "userDisplayName": "Synthetic sign-in user",
            "userPrincipalName": "user@example.invalid",
            "appId": identifier("signin-app"),
            "appDisplayName": "Synthetic application",
            "resourceId": identifier("signin-resource"),
            "resourceDisplayName": "Synthetic resource",
            "ipAddress": f"192.0.2.{10 + index % 4}",
            "clientAppUsed": "Browser",
            "correlationId": identifier(f"signin:{index}:correlation"),
            "isInteractive": True,
            "conditionalAccessStatus": "notApplied",
            "status": {"errorCode": 0 if index % 4 == 3 else 50126, "failureReason": None},
            "riskLevelDuringSignIn": "high" if index == 3 else "hidden",
            "riskState": "none",
            "deviceDetail": {"deviceId": None},
            "appliedConditionalAccessPolicies": [],
        }
        if index == 8:
            raw["status"] = None
        if index == 9:
            raw["userId"] = None
        if index == 10:
            raw["createdDateTime"] = None
            raw["riskLevelDuringSignIn"] = None
        events.append(raw)
    # Same display identifiers never rescue an absent immutable user ID.
    other_unknown = copy.deepcopy(events[9])
    other_unknown["id"] = identifier("signin:unknown-second")
    events.append(other_unknown)
    sha = write_json(directory / "signins.json", {"value": events})
    manifest(
        directory,
        "azure.entra.signin",
        "entra-signin-synthetic-v1",
        [{"path": "signins.json", "format": "graph-signin-json", "sha256": sha}],
    )


if __name__ == "__main__":
    generate_audit()
    generate_signins()
