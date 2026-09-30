# Microsoft Graph v1.0 Entra sources

`azure.entra.signin` accepts one Graph v1.0 sign-in object or a `value` collection, using manifest format `graph-signin-json`. `azure.entra.audit` accepts one Graph v1.0 directory audit object or a `value` collection, using `graph-directory-audit-json`. Arrays without the Graph envelope, JSONL, beta schemas and diagnostic-settings exports are not supported representations. An `@odata.nextLink` is retained in the artifact but never followed: supplied pages alone define the corpus. No Graph API, tenant, license or credentials are needed.

## Provenance and usage

Primary schemas: [signIn](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0), [signInStatus](https://learn.microsoft.com/en-us/graph/api/resources/signinstatus?view=graph-rest-1.0), [directoryAudit](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0), [targetResource](https://learn.microsoft.com/en-us/graph/api/resources/targetresource?view=graph-rest-1.0), [auditActivityInitiator](https://learn.microsoft.com/en-us/graph/api/resources/auditactivityinitiator?view=graph-rest-1.0), and [appIdentity](https://learn.microsoft.com/en-us/graph/api/resources/appidentity?view=graph-rest-1.0). Supported operation names are from Microsoft's [audit activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities).

Exact response excerpts from the first examples on [list signIns](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0) and [list directoryAudits](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0) are retained under each source's `documentation/` directory. Both original sources mark these examples shortened/truncated. The sign-in example also contains a trailing comma that is invalid JSON. The audit example uses uppercase `Type` although the resource schema defines lowercase `type`. These are documentation evidence only, never repaired or imported as validated official event fixtures. Their original excerpt hashes, source-document hashes, source URLs and extraction description appear in `provenance.json`.

Attribution: Microsoft Corporation and Microsoft Graph documentation contributors. The [documentation repository license](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/LICENSE) is CC-BY-4.0; [code examples are MIT](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/LICENSE-CODE). The original MIT notice is retained alongside the excerpts. Documentation usage follows [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/). No endorsement is implied.

Executable fixtures are independently generated under MIT by `scripts/generate_entra.py`. It creates deterministic fictional UUIDs, explicit fictional tenant, reserved example identities/IPs, valid timestamps, outcomes, target arrays and audit operation names from the schemas. It does not edit the vendor excerpts into runnable events. It deliberately omits optional operation-specific `modifiedProperties` semantics rather than claiming an undocumented layout. Schema-derived operations/target typing have synthetic validation only. Ground truth is separate from detector inputs in `evaluation/entra-ground-truth.json`.

## Exact normalized mappings

| Field | Sign-ins | Directory audits |
|---|---|---|
| Provider/source | `azure` / `azure.entra.signin` | `azure` / `azure.entra.audit` |
| Time | `createdDateTime`, timezone required | `activityDateTime`, timezone required |
| Source event ID | `id` | `id` |
| Service/action | fixed `Microsoft Entra ID` / `signIn` | fixed `Microsoft Entra ID` / `activityDisplayName`; absent action is `unknown` with quality flag |
| Actor | `userId`, type `User` when present | `initiatedBy.user.id`, type `User`; otherwise `initiatedBy.app.servicePrincipalId`, type `ServicePrincipal`; ambiguous simultaneous user/app stays unknown |
| Outcome | integer `status.errorCode` 0 success, nonzero failure; missing/null/string/bool unknown | explicit `result=success/failure`; timeout or other values unknown |
| Error code | nonzero numeric error code as text | unknown; resultReason retained in extensions |
| Source address/IP | `ipAddress`; IP only if valid | `initiatedBy.user.ipAddress`; IP only if valid |
| Resources | explicit `appId` and `resourceId` tagged by field | unmodified `targetResources` array if present |
| Authentication | status, isInteractive, Conditional Access state; MFA satisfaction unknown | unknown |
| Scope | `azure.tenant` with collection tenant from manifest | same |
| Provider-specific fields | all original object properties in `extensions.graph` | all original object properties in `extensions.graph` |

Timestamp fractions up to nine digits are accepted. The common timestamp stores microseconds and `extensions.timestamp_submicrosecond_ns` retains the remaining nanoseconds; rule and hunt window comparisons include that remainder, so a submicrosecond boundary is not rounded into a match. Fractions beyond nine digits are rejected.

The entire record is preserved canonically as `raw`; original artifact bytes and record pointers remain in the common evidence store. `account_id`, region, AWS-style ARN and credential ID are unknown. No email, username, display name or IP establishes an identity join. The app's application ID is not silently substituted for its tenant-local service-principal object ID.

A collection manifest may explicitly supply tenant through `scope_id` and/or `tenant_id`; when both exist they must agree. Missing collection tenant remains unknown even if a guest's `homeTenantId` exists in raw data. A tenant is not an Azure subscription, AWS account or GCP project. UIDs and source-ID conflicts include provider/source and collection scope via the existing v2 identity contract. No AWS ID changes occur.

Official executable fixture validated: **NO**, presentation excerpts retained. Public-schema synthetic corpus validated: **YES** when parser/tests/evaluation pass. Live account validated: **NO**.
