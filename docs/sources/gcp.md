# GCP Cloud Audit Logs source

`gcp.audit` accepts one explicit representation: Cloud Logging JSON `LogEntry` objects whose `protoPayload.@type` is `type.googleapis.com/google.cloud.audit.AuditLog`. The `gcp-audit-json` file format accepts one object, a top-level object array, or a Logging API `entries` array. It does not support BigQuery export table layouts, Pub/Sub wrappers, JSON strings inside `jsonPayload`, or text logs. Required structural fields are typed `protoPayload`, `serviceName` and `methodName`; other missing fields remain unknown. Original record JSON and artifact bytes are retained.

## Public sources and usage

All references were consulted on 2026-09-30. No live project or credentials were used.

| Source | Use |
| --- | --- |
| [LogEntry](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry) | Envelope, timestamp, insertId and logName |
| [AuditLog](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog) | Authentication, request/response, status, source address and optional fields |
| [Understanding audit logs](https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs) | Audit type, serviceData formats, operation completion |
| [Service-account examples](https://docs.cloud.google.com/iam/docs/audit-logging/examples-service-accounts) | Abbreviated official excerpts, exact key-use field, coverage caveats |
| [ServiceAccountKey](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys) | Response.name resource format |
| [IAM audit logging](https://docs.cloud.google.com/iam/docs/audit-logging) and [Resource Manager auditing](https://docs.cloud.google.com/resource-manager/docs/audit-logging) | API method names |
| [Cloud Storage auditing](https://docs.cloud.google.com/storage/docs/audit-logging) | Bucket policy changes, resource type and logging limitations |
| [Google IAM AuditData](https://github.com/googleapis/googleapis/blob/master/google/iam/v1/logging/audit_data.proto) and [PolicyDelta](https://github.com/googleapis/googleapis/blob/master/google/iam/v1/policy.proto) | Exact delta structure |
| [Google public-bucket detection example](https://cloud.google.com/blog/products/identity-security/announcing-cloud-analytics-googles-latest-partnership-with-mitre) | storage.setIamPermissions ADD to allUsers semantics |
| [Public access prevention](https://docs.cloud.google.com/storage/docs/public-access-prevention) | Limits on effective access inference |

Google documentation footers identify CC BY 4.0 for prose and Apache-2.0 for code examples, subject to page-specific notices; see [Google site policies](https://developers.google.com/terms/site-policies). Google LLC is credited for the retained excerpts. The project-generated fixtures and code are independently written and subject to this repository's [proprietary terms](../../LICENSE). Public schemas informed field names and valid representations; no private telemetry or private keys are included.

`fixtures/gcp/documentation` preserves decoded HTML code-block text without editing, plus source URL, retrieval date, page SHA-256, per-excerpt SHA-256 and extraction method. The vendor explicitly abbreviates these examples. The key-creation excerpt also contains a trailing comma: it is deliberately **not repaired**. The valid project-grant excerpt is only a partial documentation example, not a complete validated official fixture. A test demonstrates its missing values remain unknown. **Official complete-fixture validation: NO (documentation excerpts only). Live validation: NO.**

`scripts/generate_gcp.py` independently generates `fixtures/gcp/synthetic`, deterministically. It creates invented log owners, event IDs, timestamps, non-secret key resource names, principals, request/response values and policy deltas. All status codes, omissions, timestamps and telemetry-loss variations are generated explicitly. The corpus is neither an official sample nor a repaired official excerpt. A separate UID-based `evaluation/gcp-ground-truth.json` stores intent, expected anchors and telemetry completeness; detector input contains no labels.

## Exact normalized mappings

| Event field | Source and interpretation |
| --- | --- |
| provider / source | `gcp` / `gcp.audit` |
| scope_type / scope_id | `logName` prefix `projects/P`, `organizations/O`, or `folders/F` maps to `gcp.project/P`, `gcp.organization/O`, `gcp.folder/F`; scope identifies the **log owner**, not necessarily resource ownership |
| tenant_id / account_id | NULL; no Azure/AWS equivalence |
| timestamp | `timestamp`, timezone required if present; retained raw timestamp keeps full vendor precision |
| source_event_id | Compact canonical JSON `[insertId, original_timestamp_text]`, only when both nonempty; both original values remain in extensions/raw. Conflict checks add provider/source/scope. Raw timestamp text avoids dropping nanoseconds from identity. Equivalent timestamp spellings are not canonicalized into one source ID. |
| event_uid | Existing v2 provider/source/scope/raw domain-separated hash; AWS scheme unchanged |
| service / action | `protoPayload.serviceName` / `methodName`, no case rewriting |
| actor_id | `authenticationInfo.principalSubject` only; `principalEmail` stays in authentication/extensions, with no email identity inference |
| actor_type / actor_arn | NULL; no guessed principal classification or AWS identifier |
| credential_id | `authenticationInfo.serviceAccountKeyName` verbatim |
| source_address / source_ip | `requestMetadata.callerIp`; source_ip only if an actual IP, otherwise unknown |
| outcome | Numeric status.code zero = success, nonzero = failure; explicitly empty status = success. Missing/null status or nonnumeric code = unknown. A nonfinal `operation` makes otherwise successful outcome unknown. Success records an API outcome, not durable state. |
| region | NULL; GCP resource locations may be multi-valued or global and remain in extensions |
| resources | `protoPayload.resourceName` if supplied |
| authentication / privilege_context | Original authenticationInfo / authorizationInfo |
| extensions | Original protoPayload, resource, operation, logName, insertId and timestamp, plus `submicrosecond_nanos` retaining the timestamp's residual 0..999 nanoseconds |

Billing-account log scopes are currently unsupported and remain unknown with a quality flag; no collection scope is invented. Resource label project IDs are not substituted for log ownership. Rules requiring scope exclude unknown scope. There is no cross-project alias mapping, cloud identity equivalence, or causal attribution from matching email/IP/display names.

When log ownership is unknown, equal source IDs with different raw content conservatively conflict within the shared unknown-scope domain. This does not prove that the two events have the same real owner. A supported, explicit `logName` scope is needed to separate them; the parser does not discard an available `insertId`/timestamp pair to avoid this integrity check.

The common timestamp uses Python/DuckDB microsecond precision. The adapter retains residual nanoseconds in extensions, and the GCP sequence rule/hunt adds that residual to integer microsecond differences for exact ordering and window boundaries up to the documented nine fractional digits. More than nine fractional digits are rejected. Generic timeline display uses common timestamp precision; raw records retain all digits. Absent required fields, hidden key names and omitted response details limit recall; raw retention does not reconstruct absent telemetry.
