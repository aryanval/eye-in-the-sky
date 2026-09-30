# Azure Activity Log: supported representation and provenance

`azure.activity` accepts `azure-activity-rest-json`: a complete REST **EventData**
object or a REST **EventDataCollection** object with `value` containing objects.
The [Azure Monitor Activity Logs List API, version 2015-04-01](https://learn.microsoft.com/en-us/rest/api/monitor/activity-logs/list?view=rest-monitor-2015-04-01)
defines this representation. Pagination links are retained in the artifact and
never followed. The parser does not accept Event Hubs/diagnostic `records`
exports, Log Analytics table rows, or claim every Azure export shape is supported.

## Mapping

| Common field | Exact source and interpretation |
| --- | --- |
| `source_event_id` | `eventDataId`; absence stays null |
| `timestamp` | `eventTimestamp` as UTC; `submissionTimestamp` is not substituted |
| `service` | `resourceProviderName.value`; when absent, the known source name `azure.monitor.activity` is used and the missing provider is flagged |
| `action` | Required invariant `operationName.value`; localized text is not substituted |
| `scope_type` | `azure.subscription` for this subscription REST source |
| `scope_id` | `subscriptionId`, or explicit manifest subscription context when absent |
| `tenant_id` | EventData `tenantId`, or explicit manifest tenant context when absent; never inferred from token claims |
| `actor_id` | Exact `claims["http://schemas.microsoft.com/identity/claims/objectidentifier"]` |
| `source_address`, `source_ip` | `httpRequest.clientIpAddress`; only valid literal IPs populate `source_ip` |
| `outcome` | Invariant `status.value`: `Succeeded` → success; `Failed` → failure; all other, null and absent statuses → unknown |
| `resources` | `resourceId` when present; absence is not reconstructed from `id` or operation text |
| `authentication`, `privilege_context` | Original `claims` and `authorization`, respectively; absent nested objects stay JSON null |

The provider-specific token tenant is retained as `extensions.actor_tenant_id`.
It namespaces the actor object claim; it does not establish the resource tenant.
`caller`, authorization, operation/correlation IDs, category, status/substatus,
properties and scope/provider values are retained in extensions. All fields,
including unmapped additions and explicit nulls, remain in `raw`. Actor type,
credential identifier, region and AWS `account_id` remain null: this source does
not defensibly establish those common fields. No email, username, IP or display
name establishes identity equivalence.

Timestamps accept timezone-bearing RFC3339 with up to nine fractional digits.
The common datetime/store field has microsecond precision. Any submicrosecond
remainder is retained as `extensions.timestamp_submicrosecond_ns` and flagged
in quality metadata. The Azure rule includes this remainder in ordering and
window comparisons, so a record 100 ns past the inclusive boundary is excluded.
The full original timestamp remains unchanged in raw evidence.

Explicit subscription or resource-tenant values conflicting with declared
collection context reject ingestion transactionally. Missing scope remains
unknown and the detection does not correlate unknown scopes. The existing v2
event identity binds provider, source, typed subscription scope, resource tenant
and exact canonical raw event. Source-ID conflicts are checked within that same
domain; there is no AWS ID collision and no schema migration.

## Official example

The [Microsoft REST API specification example](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/monitor/resource-manager/Microsoft.Insights/Insights/stable/2015-04-01/examples/GetActivityLogsFiltered.json)
is valid complete JSON. `fixtures/azure/activity/official/GetActivityLogsFiltered.source.json`
retains the original downloaded bytes. `sample-01.json` is the exact byte substring
at `/responses/200/body`; it changes no event value or internal whitespace.
The official fixture manifest records both SHA-256 hashes and this extraction.
Its example token identifiers include non-UUID placeholder text, which is kept
unchanged. Its resource tenant is absent and remains unknown. The sample is
illustrative documentation, never described as live activity.

The source repository's [MIT license](https://github.com/Azure/azure-rest-api-specs/blob/main/LICENSE)
permits redistribution with attribution; `LICENSE.microsoft.txt` retains the
copyright and permission notice. Microsoft Learn schema/operation pages are
linked as design references, with no copied article text. The official input is
parsed and its retained evidence is checked independently from synthetic data.

## Synthetic corpus

`scripts/generate_azure_activity.py` authors new EventData using the public schema
and the documented [Monitor](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/monitor)
and [Management and governance](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/management-and-governance)
operation names. It generates fictional UUIDs, dates, actor claims, scopes,
operation/status fields, resource IDs and documentation-range IP addresses.
These records are independently authored synthetic examples under this project's
MIT license; none is a repaired official event. Seventeen scenarios contain
malicious, benign, ambiguous, missing-telemetry and background events. Separate
ground truth identifies exact UID anchor sets, including an uncollected record.
No label, scenario name or authorization verdict enters detector input.

The generator is deterministic. Evaluation intentionally retains authorized
lookalike alerts and delayed, different-actor and missing-telemetry misses.
Live account validation: **NO**. No account, billing, credential or network call
is needed to ingest, detect or evaluate the checked-in corpus.
