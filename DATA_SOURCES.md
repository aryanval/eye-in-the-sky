# Data sources and provenance

No employer/customer repository, data, prompts, schemas, architecture, detections
or incident sequences were inspected or reused. No telemetry was sanitized from
work systems or reconstructed from memory. All scenario details were invented
for this project using the public references below.

Every import requires a manifest declaring provider, source format, source URLs,
license/usage status, modification status, limitations and file hashes. The four
recognized categories are `official sample`, `synthetic`, `public dataset`, and
`personally generated live event`. A public URL alone is not an open license.

## Included dataset inventory

| Dataset | Provider/source | Category | Source URL | License / usage | Modified? | Limitations |
|---|---|---|---|---|---|---|
| `aws-official-examples-v1` | AWS CloudTrail | official sample | [AWS example logs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html) | Documentation excerpts attributed under CC BY-SA 4.0; AWS separately licenses embedded code MIT-0 | No event values changed; HTML code-block text extracted and complete API examples selected | Seven illustrative events; placeholders; not live personal telemetry, production prevalence or comprehensive schema coverage |
| `aws-synthetic-scenarios-v1` | AWS CloudTrail-shaped JSON | synthetic | [CloudTrail record reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) plus the API references below | Original project content under MIT | Independently generated; not modified employer or vendor event records. Deliberate omissions belong to the scenario design | 24 author-defined scenarios, fictional authorization labels, incomplete cases and repeated background; no actual AWS execution |

File-level provenance is in the [official manifest](fixtures/aws/official/manifest.json)
and [synthetic manifest](fixtures/aws/synthetic/manifest.json). The former records
the public page retrieval timestamp and page hash. Both enumerate every fixture
file and SHA-256. Evaluation labels are independently stored in
[ground_truth.json](evaluation/ground_truth.json), and result files are derived
evaluation artifacts rather than another telemetry source.

Official samples cover StartInstances, StopInstances, CreateKeyPair, CreateUser,
AddUserToGroup, CreateRole and a failed UpdateTrail. They validate parser behavior;
the two detection sequences are explicitly synthetic. Original example values
remain unchanged, including public placeholder identifiers. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [AWS terms](https://aws.amazon.com/terms/).

The synthetic generator uses these official operation references:

- [CreateAccessKey](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html)
- [AttachUserPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html)
- [AttachRolePolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html)
- [StopLogging](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html)
- [StartLogging](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StartLogging.html)
- [AuthorizeSecurityGroupIngress](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html)

Synthetic IPs use documentation ranges. Account IDs, principals, credentials and
event UUIDs are invented; key identifiers have no associated secret credentials.
Source filenames and scenario labels do not participate in detection predicates.
The scenario time origin is fictional and has no connection to any incident.

## Reproducibility and acquisition

`scripts/generate_synthetic.py` deterministically emits the committed synthetic
files and separate label manifest. It runs no attack commands or cloud API calls.
`scripts/source_official.py` fetches only the named public AWS documentation page.
It is an optional source-maintenance operation, not part of installation, testing,
evaluation or the walkthrough. Re-fetching requires reviewing changes, notices
and dataset versioning before accepting new evidence. Existing evaluations are
never silently updated to match new inputs.

## Researched references reserved for later phases

These links form the source inventory for the next phase. They are **not imported
datasets, implemented parsers or validated telemetry** in Phase 1. Keeping a
source inventory does not establish implemented or validated provider support.

| Planned source | Public schema/example | Usage status and limits |
|---|---|---|
| Azure Activity | [REST/portal schema and samples](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log-schema) | Export shapes differ. Microsoft documentation repository uses [CC BY 4.0](https://github.com/MicrosoftDocs/azure-monitor-docs/blob/main/LICENSE) with a separate [MIT code license](https://github.com/MicrosoftDocs/azure-monitor-docs/blob/main/LICENSE-CODE). No dataset imported. |
| Entra sign-ins | [Graph v1.0 schema](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0), [responses](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0) | Static references require no tenant. Actual API access has separate permissions/licensing requirements; no API collection planned in Phase 1. |
| Entra audits | [Graph v1.0 schema](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0), [responses](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0) | Graph documentation has [CC BY 4.0](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/LICENSE) and a separate [MIT code license](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/LICENSE-CODE). No dataset imported. |
| GCP Cloud Audit Logs | [LogEntry](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry), [AuditLog](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog), [service-account examples](https://docs.cloud.google.com/iam/docs/audit-logging/examples-service-accounts) | The examples include abbreviated records and some presentation syntax unsuitable for direct JSON parsing. Any future repair/addition must be disclosed. Documentation states CC BY 4.0 / Apache 2.0 for code samples. No dataset imported. |

There are no openly licensed third-party security datasets or personally generated
live events in this release. No personal AWS, Azure or GCP account was created.
