# Data sources and provenance

Implementation and synthetic scenarios are independently authored using public
vendor schemas and examples. Synthetic identities, times, actions and intent
labels are fictional. Runtime validation needs no cloud account or credentials.

Every import requires a manifest declaring provider/source, format, source URLs,
license/usage, modifications, limitations and file hashes. Categories are
`official sample`, `synthetic`, `public dataset`, and `personally generated live event`.
A public URL alone is not an open license. This release includes only the first
two categories; **live validation remains NO for every source**.

## Included source inventory

| Source | Supported representation | Official executable fixtures | Independently generated corpus | Exact mappings and public references |
|---|---|---|---|---|
| AWS CloudTrail | Event object, `Records` wrapper, JSONL | Seven unchanged selected API examples | 24 scenarios; 240 unique events, 264 deliveries | [CloudTrail record reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html), [mapping](ARCHITECTURE.md#normalized-model-and-mapping) |
| Azure Activity | REST EventData object or `value` collection, API 2015-04-01 | One unchanged event from Microsoft REST API specification | 17 scenarios; 84 events | [Source details](docs/sources/azure-activity.md) |
| Entra sign-ins | Graph v1.0 signIn object or `value` collection | None; original abbreviated HTTP excerpt retained | 13 records for exploratory hunt validation | [Source details](docs/sources/entra.md) |
| Entra directory audits | Graph v1.0 directoryAudit object or `value` collection | None; original abbreviated HTTP excerpt retained | 18 scenarios; 69 events | [Source details](docs/sources/entra.md) |
| GCP Cloud Audit Logs | LogEntry AuditLog object, array or `entries` collection | None; original abbreviated excerpts retained | 30 scenarios across two rules; 73 events | [Source details](docs/sources/gcp.md) |

The executable manifests are under `fixtures/aws/{official,synthetic}`,
`fixtures/azure/activity/{official,synthetic}`,
`fixtures/azure/entra-{signin,audit}/synthetic` and `fixtures/gcp/synthetic`.
They enumerate file hashes and contain full provenance. Scenario truth is
separately stored under `evaluation/`; result reports are derived artifacts,
not another telemetry source. Background noise is included in the event totals.

## Official examples and incomplete excerpts

The [AWS manifest](fixtures/aws/official/manifest.json) records extraction from
[AWS example logs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html),
retrieval timestamp, page hash and file hashes. The seven events cover
StartInstances, StopInstances, CreateKeyPair, CreateUser, AddUserToGroup,
CreateRole and failed UpdateTrail. Values are unchanged. These illustrate
parsing; the detection sequences are synthetic.

The [Azure manifest](fixtures/azure/activity/official/manifest.json) identifies
the complete original Microsoft REST API example and the exact byte substring
extracted as its response body. Both artifacts are retained; no event values or
placeholder text are edited.

Entra examples are explicitly shortened and one has invalid JSON punctuation;
the directory-audit excerpt also has presentation/schema casing differences.
GCP examples explicitly show only relevant fields and the key-creation excerpt
has invalid JSON punctuation. Files under those sources' `documentation/`
directories preserve the original excerpts, hashes, URLs, extraction method and
notices. **They are not silently repaired or imported as complete official fixtures.**
A GCP test parses the valid partial excerpt only to check missing-value behavior;
that is not complete official-fixture validation.

Vendor material retains its upstream terms. AWS documentation excerpts use
CC BY-SA 4.0 attribution, with separate MIT-0 code terms. Microsoft's REST API
specification example is MIT. Microsoft Graph documentation is CC BY 4.0 with
MIT code terms. Google's documentation uses CC BY 4.0 and its code samples
Apache-2.0, subject to page-specific notices. See [notices](THIRD_PARTY_NOTICES.md)
and each source's retained provenance for attribution and exact transformations.

## Synthetic generation and reproduction

The generators run locally with no API calls or attack commands:

- `scripts/generate_synthetic.py`: preserved AWS corpus and labels.
- `scripts/generate_azure_activity.py`: new REST EventData and UID anchors.
- `scripts/generate_entra.py`: new Graph audit/sign-in objects and audit UID anchors.
- `scripts/generate_gcp.py`: new AuditLog LogEntry records and UID anchors.

They generate fictional IDs, documentation/example addresses, timestamps,
operation fields, deliberate omissions and background activity. No actual secret
credentials are generated. Fields are based on the public schema; operation-specific
coverage limits are stated in the linked designs. The original vendor excerpts
are not templates that get repaired into executable fixtures. Source filenames,
authorization narratives and labels never participate in detection predicates.

Generators reproduce committed fixtures and truth byte for byte in tests. The
optional AWS `scripts/source_official.py` fetcher is separate from runtime,
installation, tests and demonstration. Re-fetching any vendor source requires
reviewing provenance, notices and dataset versioning; existing reports are retained.
There is no external security dataset or production prevalence estimate.
