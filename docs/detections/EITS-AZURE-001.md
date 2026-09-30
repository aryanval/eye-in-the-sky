# EITS-AZURE-001: diagnostic setting deletion followed by role assignment

## Design and public fields

This design was recorded before the executable SQL. The rule uses the Azure Monitor
[Activity Logs REST EventData representation](https://learn.microsoft.com/en-us/rest/api/monitor/activity-logs/list?view=rest-monitor-2015-04-01).
It requires `eventTimestamp`, `operationName.value`, `status.value`, `subscriptionId`,
and the exact `claims["http://schemas.microsoft.com/identity/claims/objectidentifier"]`
and `claims["http://schemas.microsoft.com/identity/claims/tenantid"]` values.
Resource tenant context must also be present as `tenantId` or validated manifest
`collection_scope.tenant_id`. `eventDataId` identifies source records, while all
supporting evidence uses content- and scope-bound event UIDs. `resourceId` is
reported as context when available, but is not required to infer a relation
between the changed resources.

The first successful operation is `Microsoft.Insights/diagnosticSettings/delete`;
the later successful operation is `Microsoft.Authorization/roleAssignments/write`.
Microsoft documents the [diagnostic-setting deletion permission](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/monitor)
and the [role-assignment creation permission](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/management-and-governance).
Their invariant operation names are compared case-insensitively. Both records
must have `status.value = Succeeded`, the same known subscription and resource
tenant, and the same exact object-ID and actor-tenant claims. The time constraint
is `0 < elapsed <= 30 minutes`. Equal timestamps do not establish order.
The rule uses the retained submicrosecond timestamp remainder to resolve exact
ordering and inclusive boundaries when REST timestamps have seven to nine
fractional digits; the common store's microsecond truncation cannot extend the window.

Deleting a diagnostic setting can reduce exported telemetry; a subsequent role
assignment is a security-relevant access-control change. The combination warrants
investigation for attempted visibility reduction around permission changes.
The rule does not assert that every role assignment is privileged.

Approved monitoring migrations followed by access provisioning can produce the
same two records. A replacement diagnostic setting can also exist between the
events. Both benign patterns remain in evaluation and can alert; no speculative
allowlist or absence-of-logging inference suppresses them.

These records cannot establish malicious intent, change authorization, whether
the deleted setting covered the later operation, the absence of other exports,
the granted role or recipient when request details are absent, effective access,
or actual use of the assignment. The token tenant is an actor namespace; it is
not silently substituted for the resource tenant. No IP, caller email, display
name, or cross-cloud identity join is used.

## Operational interpretation

Required telemetry is completed Azure control-plane Activity Log records with
the fields above. Observed facts are the two reported successful operations,
their scope, actor claims, timestamps and retained resource IDs. The inference
is possible defense impairment followed by permission modification. Obtain
change records, diagnostic-setting snapshots, export-delivery evidence, the
role assignment and role definition, target principal, and follow-on activity
before calling the sequence malicious.

ATT&CK coverage is behavioral and conditional: [T1685.002, Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/)
and [T1098.003, Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/).
An alert does not prove that either technique succeeded.

Tune only with explicit, expiring scope/actor/change approvals and measure the
lost malicious coverage. Delayed activity, unknown actor identifiers, missing
records, unknown resource tenant context and different actors are outside the
correlation. This source is the REST EventData shape, not all Azure export shapes.

## Evaluation

The independent synthetic corpus includes malicious sequences, an inclusive
30-minute boundary, delayed activity, missing records/identity/time, authorized
lookalikes, intervening restoration, an ambiguous sequence, failed operations,
equal timestamps, different actors/scopes and unrelated administrative noise.
Labels and exact expected event UID sets are stored only in
`evaluation/azure-activity-ground-truth.json`. The baseline is retained without
tuning. Its 17 scenarios yield **TP 2, FP 2, FN 7, TN 5**; precision **0.5**,
recall **0.222222**, complete-telemetry recall **0.4**. The one ambiguous scenario
alerts and is excluded from the binary metrics. The two false positives are
authorized workflows, including the replacement-export case. Complete-telemetry
misses are delayed activity, coordinated different actors, and equal timestamps;
four further misses have incomplete records or required fields. These results
are also recorded in the Phase 2 evaluation report; synthetic precision and recall
do not estimate deployment prevalence.
