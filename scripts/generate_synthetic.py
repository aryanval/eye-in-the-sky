"""Original fictional scenarios based only on public AWS formats.

No attack commands run. No credentials, cloud APIs, employer materials, or
external datasets are accessed. Labels stay in evaluation/ground_truth.json.
"""

import copy
import hashlib
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
SOURCES = [
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html",
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html",
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html",
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StartLogging.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html",
]


def identifier(prefix, value, length=20):
    return prefix + hashlib.sha256(value.encode()).hexdigest().upper()[: length - len(prefix)]


def event(number, tag, action, minute=0, service="iam.amazonaws.com", request=None):
    account = f"{900000000000 + number:012d}"
    principal = identifier("AIDA", f"operator-{number}", 21)
    return {
        "eventVersion": "1.09",
        "eventTime": (datetime(2025, 2, 3, 12, tzinfo=timezone.utc) + timedelta(minutes=minute))
        .isoformat()
        .replace("+00:00", "Z"),
        "eventSource": service,
        "eventName": action,
        "awsRegion": "us-east-1",
        "eventID": str(uuid.uuid5(uuid.NAMESPACE_URL, f"eye-in-the-sky:fixture-v1:{number}:{tag}")),
        "requestID": str(uuid.uuid5(uuid.NAMESPACE_URL, f"eye-in-the-sky:request:{number}:{tag}")),
        "userIdentity": {
            "type": "IAMUser",
            "principalId": principal,
            "accountId": account,
            "arn": f"arn:aws:iam::{account}:user/operator-{number}",
            "userName": f"operator-{number}",
            "accessKeyId": identifier("AKIA", f"original-{number}"),
        },
        "sourceIPAddress": "192.0.2.10",
        "userAgent": "eye-in-the-sky/synthetic-fixture",
        "requestParameters": request or {},
        "responseElements": None,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "eventCategory": "Management",
        "readOnly": False,
        "recipientAccountId": account,
    }


def key_pair(number):
    issued = identifier("AKIA", f"issued-{number}")
    a = event(number, "creation", "CreateAccessKey", request={"userName": f"worker-{number}"})
    a["responseElements"] = {
        "accessKey": {
            "accessKeyId": issued,
            "userName": f"worker-{number}",
            "status": "Active",
            "createDate": a["eventTime"],
        }
    }
    b = event(
        number,
        "attachment",
        "AttachUserPolicy",
        5,
        request={"userName": f"recipient-{number}", "policyArn": ADMIN},
    )
    b["userIdentity"].update(
        {
            "principalId": identifier("AIDA", f"worker-{number}", 21),
            "arn": f"arn:aws:iam::{b['recipientAccountId']}:user/worker-{number}",
            "userName": f"worker-{number}",
            "accessKeyId": issued,
        }
    )
    return a, b


def permission(port=22, cidr="0.0.0.0/0", protocol="tcp"):
    value = {"ipProtocol": protocol}
    if protocol != "-1":
        value.update({"fromPort": port, "toPort": port})
    if ":" in cidr:
        value["ipv6Ranges"] = {"items": [{"cidrIpv6": cidr}]}
    else:
        value["ipRanges"] = {"items": [{"cidrIp": cidr}]}
    return value


def logging_pair(number):
    a = event(
        number,
        "stop",
        "StopLogging",
        service="cloudtrail.amazonaws.com",
        request={"name": f"arn:aws:cloudtrail:us-east-1:{900000000000 + number}:trail/example"},
    )
    b = event(
        number,
        "ingress",
        "AuthorizeSecurityGroupIngress",
        5,
        "ec2.amazonaws.com",
        {"groupId": f"sg-{number:017x}", "ipPermissions": {"items": [permission()]}},
    )
    b["responseElements"] = {"_return": True}
    return a, b


def main():
    directory = ROOT / "fixtures/aws/synthetic"
    specifications, truth = [], []
    narratives1 = [
        (
            "malicious",
            True,
            "Unauthorized new credential used to attach AdministratorAccess to a user.",
        ),
        ("malicious", True, "Unauthorized new credential used for a role policy attachment."),
        (
            "malicious",
            True,
            "Credential misuse delayed for 45 minutes; a window-related miss is possible.",
        ),
        (
            "malicious",
            True,
            "Credential used to assume a role; temporary credentials perform the attachment.",
        ),
        ("benign", True, "Approved key rotation followed only by instance inventory."),
        (
            "benign",
            True,
            "Approved bootstrap attaches AdministratorAccess using a new key; logs cannot reveal approval.",
        ),
        ("benign", True, "Authorized operator makes a denied policy-attachment request."),
        (
            "benign",
            True,
            "Unrelated authorized attachment uses an older credential, not the created key.",
        ),
        ("ambiguous", True, "New-key policy attachment; authorization and intent are unavailable."),
        (
            "ambiguous",
            True,
            "Created key has no subsequent use in the supplied observation window.",
        ),
        (
            "malicious",
            False,
            "Unauthorized attachment follows key creation, but the issued-key response field is missing.",
        ),
        (
            "malicious",
            False,
            "Unauthorized attachment occurred in the fictional scenario but its event was dropped.",
        ),
    ]
    narratives2 = [
        ("malicious", True, "Unauthorized logging stop followed by public IPv4 SSH permission."),
        (
            "malicious",
            True,
            "Unauthorized logging stop followed by public IPv6 all-protocol permission.",
        ),
        ("malicious", True, "Unauthorized public ingress occurs 45 minutes after logging stop."),
        (
            "malicious",
            True,
            "Attacker restores the trail after a brief stop, then makes an unauthorized public ingress change.",
        ),
        ("benign", True, "Approved trail migration accompanies public HTTP service provisioning."),
        (
            "benign",
            True,
            "Authorized emergency public SSH during trail maintenance; permission context is absent from logs.",
        ),
        (
            "benign",
            True,
            "Approved maintenance restores logging before an approved public RDP change.",
        ),
        (
            "benign",
            True,
            "Public HTTP and private SSH are different permission entries; SSH is not public.",
        ),
        ("ambiguous", True, "Public RDP after a trail stop; change authorization unavailable."),
        (
            "ambiguous",
            False,
            "Caller credential is unavailable, preventing a defensible session join.",
        ),
        (
            "malicious",
            False,
            "Unauthorized logging stop occurred but its source event was dropped.",
        ),
        (
            "malicious",
            False,
            "Unauthorized public SSH change is recorded without ingress permission details.",
        ),
    ]
    for number in range(1, 25):
        index = (number - 1) % 12 + 1
        first = number <= 12
        label, observable, narrative = (narratives1 if first else narratives2)[index - 1]
        a, b = key_pair(number) if first else logging_pair(number)
        anchors = [a["eventID"], b["eventID"]]
        sequence = [a, b]
        if first:
            if index == 2:
                b["eventName"] = "AttachRolePolicy"
                b["requestParameters"] = {"roleName": "example-deployment", "policyArn": ADMIN}
            if index == 3:
                b["eventTime"] = "2025-02-03T12:45:00Z"
            if index == 4:
                intermediate = copy.deepcopy(b)
                intermediate.update(
                    {
                        "eventID": str(uuid.uuid5(uuid.NAMESPACE_URL, "eits:assume:4")),
                        "eventName": "AssumeRole",
                        "eventSource": "sts.amazonaws.com",
                        "eventTime": "2025-02-03T12:02:00Z",
                        "requestParameters": {
                            "roleArn": f"arn:aws:iam::{b['recipientAccountId']}:role/example-role",
                            "roleSessionName": "example-session",
                        },
                    }
                )
                sequence.append(intermediate)
                b["userIdentity"].update(
                    {
                        "type": "AssumedRole",
                        "accessKeyId": identifier("ASIA", "temporary-4"),
                        "principalId": "AROAEXAMPLE:example-session",
                        "arn": f"arn:aws:sts::{b['recipientAccountId']}:assumed-role/example-role/example-session",
                    }
                )
                b["userIdentity"].pop("userName")
            if index == 5:
                b.update(
                    {
                        "eventName": "DescribeInstances",
                        "eventSource": "ec2.amazonaws.com",
                        "requestParameters": {},
                        "readOnly": True,
                    }
                )
            if index == 7:
                b.update({"errorCode": "AccessDenied", "errorMessage": "Synthetic denied request"})
            if index == 8:
                b["userIdentity"]["accessKeyId"] = identifier("AKIA", "unrelated-8")
            if index in (10, 12):
                sequence = [a]
            if index == 11:
                a["responseElements"] = None
        else:
            if index == 2:
                b["requestParameters"]["ipPermissions"]["items"] = [
                    permission(cidr="::/0", protocol="-1")
                ]
            if index == 3:
                b["eventTime"] = "2025-02-03T12:45:00Z"
            if index in (4, 7):
                restart = event(
                    number,
                    "restart",
                    "StartLogging",
                    2,
                    "cloudtrail.amazonaws.com",
                    copy.deepcopy(a["requestParameters"]),
                )
                sequence.append(restart)
            if index == 5:
                b["requestParameters"]["ipPermissions"]["items"] = [permission(port=80)]
            if index in (7, 9):
                b["requestParameters"]["ipPermissions"]["items"] = [permission(port=3389)]
            if index == 8:
                b["requestParameters"]["ipPermissions"]["items"] = [
                    permission(port=80),
                    permission(cidr="192.0.2.0/24"),
                ]
            if index == 10:
                a["userIdentity"].pop("accessKeyId")
                b["userIdentity"].pop("accessKeyId")
            if index == 11:
                sequence = [b]
            if index == 12:
                b["requestParameters"].pop("ipPermissions")
        for noise in range(8):
            background = event(
                number,
                f"background-{noise}",
                "DescribeInstances",
                noise * 2 - 3,
                "ec2.amazonaws.com",
                {},
            )
            background["readOnly"] = True
            sequence.append(background)
        source_ids = [x["eventID"] for x in sequence]
        sequence.append(copy.deepcopy(sequence[-1]))  # Duplicate delivery must not inflate matches.
        random.Random(1000 + number).shuffle(sequence)
        filename = f"case-{number:02d}.json"
        content = (json.dumps({"Records": sequence}, indent=2) + "\n").encode()
        (directory / filename).write_bytes(content)
        specifications.append(
            {
                "path": filename,
                "format": "cloudtrail-json",
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
        truth.append(
            {
                "scenario_id": f"case-{number:02d}",
                "rule_id": "EITS-AWS-001" if first else "EITS-AWS-002",
                "split": "development" if index in (1, 3, 6, 7, 9, 11) else "holdout",
                "label": label,
                "telemetry_complete": observable,
                "narrative": narrative,
                "anchor_event_ids": anchors,
                "available_event_ids": source_ids,
            }
        )
    manifest = {
        "dataset_id": "aws-synthetic-scenarios-v1",
        "provider": "aws",
        "source": "aws.cloudtrail",
        "category": "synthetic",
        "source_urls": SOURCES,
        "license": "MIT",
        "modified": False,
        "generation": "Independently authored fictional events, deterministic generator scripts/generate_synthetic.py; never derived from employer incidents.",
        "limitations": [
            "Author-defined scenarios and labels; not empirical production prevalence",
            "No actual AWS actions were executed",
            "Some records deliberately omit telemetry to measure misses",
            "Identifiers and documentation-range IPs are fictional",
        ],
        "files": specifications,
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (ROOT / "evaluation/ground_truth.json").write_text(
        json.dumps(
            {"version": 1, "dataset_id": manifest["dataset_id"], "scenarios": truth}, indent=2
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "scenarios": len(truth),
                "records_including_duplicates": sum(
                    len(json.loads((directory / s["path"]).read_text())["Records"])
                    for s in specifications
                ),
            }
        )
    )


if __name__ == "__main__":
    main()
