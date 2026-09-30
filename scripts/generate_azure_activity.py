"""Independently generate fictional REST EventData and separate scenario labels."""

import json
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eits.adapters.azure_activity import ACTOR_TENANT, OBJECT_ID, AzureActivityAdapter
from eits.model import digest

ROOT = Path(__file__).resolve().parents[1]
SUBSCRIPTION = "10000000-0000-4000-8000-000000000001"
TENANT = "20000000-0000-4000-8000-000000000001"
DELETE = "Microsoft.Insights/diagnosticSettings/delete"
ASSIGN = "Microsoft.Authorization/roleAssignments/write"
ADAPTER = AzureActivityAdapter()


def identifier(value):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "https://example.invalid/eits/activity/" + value))


def event(case, number, action, seconds):
    stamp = datetime(2026, 1, case, 12, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    resource = (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Insights/diagnosticSettings/export"
        if "diagnosticSettings" in action
        else f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleAssignments/"
        + identifier(f"assignment/{case}/{number}")
    )
    if "networkSecurityGroups" in action:
        resource = (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/lab/providers/"
            "Microsoft.Network/networkSecurityGroups/lab"
        )
    return {
        "eventDataId": identifier(f"event/{case}/{number}"),
        "eventTimestamp": stamp.isoformat().replace("+00:00", "Z"),
        "submissionTimestamp": (stamp + timedelta(seconds=3)).isoformat().replace("+00:00", "Z"),
        "subscriptionId": SUBSCRIPTION,
        "tenantId": TENANT,
        "operationName": {"value": action},
        "resourceProviderName": {"value": action.split("/")[0]},
        "status": {"value": "Succeeded"},
        "category": {"value": "Administrative"},
        "eventName": {"value": "EndRequest"},
        "correlationId": identifier(f"operation/{case}/{number}"),
        "operationId": identifier(f"operation/{case}/{number}"),
        "resourceId": resource,
        "caller": "operator@example.invalid",
        "claims": {OBJECT_ID: identifier(f"actor/{case}"), ACTOR_TENANT: TENANT},
        "httpRequest": {
            "clientIpAddress": "192.0.2.20",
            "method": "DELETE" if action.endswith("delete") else "PUT",
        },
        "authorization": {"action": action, "scope": resource},
    }


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def generate(root=ROOT):
    directory = root / "fixtures/azure/activity/synthetic"
    descriptions = [
        (
            "malicious",
            True,
            "Unauthorized diagnostic-setting deletion followed by an access assignment.",
        ),
        (
            "malicious",
            True,
            "Unauthorized sequence exactly 30 minutes apart; inclusive upper boundary.",
        ),
        ("malicious", True, "Unauthorized access assignment delayed beyond the 30-minute window."),
        (
            "malicious",
            False,
            "Role assignment occurred but its completed source record was not collected.",
        ),
        (
            "malicious",
            False,
            "Deletion record lacks the actor object claim needed for a defensible join.",
        ),
        (
            "benign",
            True,
            "Approved monitoring migration followed by approved access provisioning; identical visible predicate.",
        ),
        (
            "ambiguous",
            True,
            "Both operations succeeded but authorization and impact are unresolved.",
        ),
        (
            "benign",
            True,
            "Diagnostic-setting deletion was denied; later role assignment was authorized.",
        ),
        (
            "malicious",
            True,
            "Two different actors coordinate the deletion and permission change; exact actor join misses it.",
        ),
        (
            "benign",
            True,
            "Independent approved operations in different subscriptions share an actor.",
        ),
        (
            "malicious",
            True,
            "Unauthorized sequence has equal recorded timestamps; source cannot establish ordering.",
        ),
        ("malicious", False, "Role assignment lacks an event timestamp."),
        (
            "benign",
            True,
            "Approved export replacement precedes approved provisioning; baseline still alerts.",
        ),
        (
            "benign",
            True,
            "Same object-ID text is in different token-tenant namespaces; operations are independent.",
        ),
        (
            "malicious",
            False,
            "Resource tenant context is absent from both records; token tenant alone is insufficient.",
        ),
        ("benign", True, "Approved role assignment precedes diagnostic-setting retirement."),
        (
            "benign",
            True,
            "Reused object-ID and subscription text in independently supplied resource-tenant scopes do not join.",
        ),
    ]
    scenarios, files = [], []
    for case, (label, complete, narrative) in enumerate(descriptions, 1):
        start, end = event(case, 1, DELETE, 0), event(case, 2, ASSIGN, 300)
        if case == 2:
            end = event(case, 2, ASSIGN.upper(), 1800)
        elif case == 3:
            end = event(case, 2, ASSIGN, 1801)
        elif case == 5:
            start["claims"].pop(OBJECT_ID)
        elif case == 8:
            start["status"] = {"value": "Failed"}
        elif case == 9:
            end["claims"][OBJECT_ID] = identifier("other-actor")
        elif case == 10:
            end["subscriptionId"] = "10000000-0000-4000-8000-000000000002"
            end["resourceId"] = end["resourceId"].replace(SUBSCRIPTION, end["subscriptionId"])
            end["authorization"]["scope"] = end["resourceId"]
        elif case == 11:
            end = event(case, 2, ASSIGN, 0)
        elif case == 12:
            end["eventTimestamp"] = None
        elif case == 14:
            end["claims"][ACTOR_TENANT] = "20000000-0000-4000-8000-000000000002"
        elif case == 15:
            start.pop("tenantId")
            end.pop("tenantId")
        elif case == 16:
            end = event(case, 2, ASSIGN, -60)
        elif case == 17:
            end["tenantId"] = "20000000-0000-4000-8000-000000000002"
        anchors = [ADAPTER.normalize(raw).event_uid for raw in (start, end)]
        observed = [start] if case == 4 else [start, end]
        noise = [
            event(case, 3, "Microsoft.Network/networkSecurityGroups/write", -60),
            event(case, 4, "Microsoft.Authorization/roleAssignments/delete", 600),
            event(
                case, 5, "Microsoft.Insights/diagnosticSettings/write", 60 if case == 13 else 2400
            ),
        ]
        for raw in noise:
            if case != 13 or raw is not noise[-1]:
                raw["claims"][OBJECT_ID] = identifier(f"noise-actor/{case}")
        observed.extend(noise)
        filename = f"case-{case:02d}.json"
        path = directory / filename
        write_json(path, {"value": observed})
        files.append(
            {"path": filename, "format": ADAPTER.formats[0], "sha256": digest(path.read_bytes())}
        )
        scenarios.append(
            {
                "scenario_id": f"azure-activity-{case:02d}",
                "rule_id": "EITS-AZURE-001",
                "split": "development" if case % 2 else "holdout",
                "label": label,
                "telemetry_complete": complete,
                "narrative": narrative,
                "anchor_event_uids": anchors,
                "available_event_uids": [ADAPTER.normalize(raw).event_uid for raw in observed],
            }
        )
    write_json(
        directory / "manifest.json",
        {
            "dataset_id": "azure-activity-synthetic-v1",
            "provider": ADAPTER.provider,
            "source": ADAPTER.source,
            "category": "synthetic",
            "source_urls": [
                "https://learn.microsoft.com/en-us/rest/api/monitor/activity-logs/list?view=rest-monitor-2015-04-01",
                "https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/monitor",
                "https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/management-and-governance",
            ],
            "license": "MIT",
            "modified": False,
            "generation": "Independently generated fictional EventData using scripts/generate_azure_activity.py and the public REST schema; identifiers, times, scopes, actors and operations were authored locally. No official sample values were repaired or relabeled.",
            "limitations": [
                "Synthetic labels do not establish production prevalence",
                "No Azure activity was executed",
                "Intent and change authorization exist only in separate evaluation labels",
                "Missing fields and omitted records intentionally measure coverage gaps",
            ],
            "files": files,
        },
    )
    write_json(
        root / "evaluation/azure-activity-ground-truth.json",
        {
            "version": 2,
            "dataset_id": "azure-activity-synthetic-v1",
            "scenarios": deepcopy(scenarios),
        },
    )


if __name__ == "__main__":
    generate()
